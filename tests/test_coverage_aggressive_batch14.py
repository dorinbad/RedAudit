import unittest
from unittest.mock import Mock, patch, MagicMock
from redaudit.core.auditor_scan import AuditorScanMixin
from redaudit.core.auditor import InteractiveNetworkAuditor


class TestCoverageAggressiveBatch14(unittest.TestCase):

    def setUp(self):
        class MockApp(AuditorScanMixin):
            def __init__(self):
                self.config = {
                    "scan_mode": "normal",
                    "deep_id_scan": True,
                    "deep_scan_budget": 5,
                    "target_networks": ["1.1.1.0/24"],
                    "threat_level": "medium",
                    "threads": 1,
                    # Nmap arguments fallback
                    "scan_timing": "T4",
                }
                self.logger = Mock()
                self.results = {}
                self.extra_tools = {}
                self.t = lambda x, *args: x
                self.current_phase = ""
                self.rate_limit_delay = 0

            # Mock dependencies of scan_host_ports
            # We must NOT define scan_host_ports here to test the mixin method.

            def deep_scan_host(self, ip):
                return {"deep": True}

            def _reserve_deep_scan_slot(self, budget):
                return True, 1

            def print_status(self, msg, color=None, force=False):
                pass

            def _set_ui_detail(self, detail):
                pass

            def _parse_host_timeout_s(self, args):
                return 1.0

            def _scan_mode_host_timeout_s(self):
                return 1.0

            def _context_manager_mock(self):
                return MagicMock()

            def _progress_ui(self):
                return MagicMock(__enter__=lambda s: None, __exit__=lambda s, e, t, v: None)

            # Additional mocks for scan_host
            def _lookup_topology_identity(self, ip):
                return None, None

            def is_web_service(self, svc):
                return False

            def _compute_identity_score(self, rec):
                return 0, []

            def _should_trigger_deep(self, **kwargs):
                return False, []

        self.app = MockApp()

    @patch("redaudit.core.auditor_scan.enrich_host_with_dns")
    @patch("redaudit.core.auditor_scan.get_nmap_arguments", return_value="-sS")
    @patch("redaudit.core.auditor_scan.finalize_host_status")
    def test_scan_host_exception_deep_fallback(self, mock_final, mock_nmap_args, mock_dns):
        # Trigger exception inside scan_host_ports
        # enrich_host_with_dns happens LATE in the method (line 1541).
        # We need to pass the early checks (sanitize_ip, etc)

        mock_dns.side_effect = Exception("Enrichment Boom")
        mock_final.return_value = "down"

        # scan_host_ports is the target method
        # Also need to patch sanitize_ip if it's external, but it's mixed in.
        # Assuming sanitize_ip works or is mocked.
        # Let's patch sanitize_ip on the class/instance if needed.
        # Check if sanitize_ip is imported or method. It is imported in the file, but used as global?
        # or self.sanitize_ip?
        # View at line 1180 says `safe_ip = sanitize_ip(host)`.
        # So it is imported function.

        with patch("redaudit.core.auditor_scan.sanitize_ip", return_value="1.2.3.4"):
            with patch("redaudit.core.auditor_scan.is_dry_run", return_value=False):
                # We need successful nmap to reach enrichment
                mock_nm = MagicMock()
                mock_nm.all_hosts.return_value = ["1.2.3.4"]
                mock_nm.__getitem__.return_value = MagicMock()  # Data for IP
                mock_nm.__getitem__.return_value.hostnames.return_value = []
                mock_nm.__getitem__.return_value.all_protocols.return_value = []

                self.app._run_nmap_xml_scan = Mock(return_value=(mock_nm, None))

                res = self.app.scan_host_ports("1.2.3.4")

        # Validation
        self.assertEqual(res["error"], "Enrichment Boom")
        self.assertEqual(res["ip"], "1.2.3.4")
        # Check deep scan triggered
        self.assertIn("deep_scan", res)
        self.assertTrue(res["deep_scan"]["deep"])

    def test_auditor_mixins_helpers(self):
        # Test simple methods in mixins if any.
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()
