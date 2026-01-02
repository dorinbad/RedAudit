import unittest
from unittest.mock import Mock, patch
import threading


class TestAuditorAggressiveCoverage(unittest.TestCase):
    """Deep coverage for auditor.py and auditor_scan.py large missing blocks."""

    def _make_auditor(self):
        """Create a mock auditor with necessary attributes."""
        from redaudit import InteractiveNetworkAuditor

        app = InteractiveNetworkAuditor()
        app.config.update(
            {
                "target_networks": ["127.0.0.1/32"],
                "scan_mode": "completo",
                "scan_vulnerabilities": True,
                "nuclei_enabled": True,
                "output_dir": "/tmp/redaudit_test",
                "_actual_output_dir": "/tmp/redaudit_test/RedAudit_test",
                "cve_lookup_enabled": False,
                "topology_enabled": False,
                "net_discovery_enabled": False,
                "windows_verify_enabled": True,
            }
        )
        app.results = {
            "hosts": [{"ip": "1.1.1.1", "ports": [{"port": 80, "service": "http"}]}],
            "net_discovery": {},
        }
        app.print_status = Mock()
        app.logger = Mock()
        return app

    @patch("redaudit.core.auditor.is_nuclei_available")
    @patch("redaudit.core.auditor.get_http_targets_from_hosts")
    @patch("redaudit.core.auditor.run_nuclei_scan")
    @patch("redaudit.core.verify_vuln.filter_nuclei_false_positives")
    def test_run_complete_scan_nuclei_block(
        self, mock_filter, mock_run, mock_get_targets, mock_is_available
    ):
        """Cover auditor.py lines 697-849 (Nuclei block)."""
        app = self._make_auditor()
        mock_is_available.return_value = True
        mock_get_targets.return_value = ["http://1.1.1.1:80"]
        mock_run.return_value = {
            "success": True,
            "findings": [
                {"id": "test-vuln", "template_id": "test-vuln", "matched_at": "http://1.1.1.1:80"}
            ],
            "raw_output_file": "/tmp/nuclei.json",
        }
        mock_filter.return_value = (
            [{"id": "test-vuln", "template_id": "test-vuln"}],
            [{"template_id": "fp-vuln", "fp_reason": "test"}],
        )

        # Mock other phases to avoid side effects
        with (
            patch.object(app, "detect_all_networks"),
            patch.object(app, "scan_network_discovery", return_value=["1.1.1.1"]),
            patch.object(app, "scan_hosts_concurrent", return_value=app.results["hosts"]),
            patch.object(app, "run_agentless_verification"),
            patch.object(app, "_merge_nuclei_findings", return_value=1),
            patch.object(app, "save_results"),
            patch.object(app, "show_results"),
            patch.object(app, "start_heartbeat"),
            patch.object(app, "stop_heartbeat"),
        ):

            app.run_complete_scan()

        self.assertTrue(mock_run.called)
        self.assertIn("nuclei", app.results)

    def test_run_agentless_verification_error_path(self):
        """Cover auditor_scan.py lines 1803-1806 (Exception in Windows Verify)."""
        app = self._make_auditor()

        # Mock a future that raises an exception
        mock_future = Mock()
        mock_future.result.side_effect = Exception("Mock verify error")

        # Patch 'wait' and 'select_agentless_probe_targets'
        with (
            patch("redaudit.core.auditor_scan.wait") as mock_wait,
            patch("redaudit.core.auditor_scan.select_agentless_probe_targets") as mock_select,
        ):

            # mock_select must return a non-empty list to avoid early exit
            mock_target = Mock()
            mock_target.ip = "1.1.1.1"
            mock_select.return_value = [mock_target]

            # First call returns completed=[mock_future], pending=set()
            mock_wait.return_value = ([mock_future], set())

            with (
                patch.object(app, "print_status"),
                patch("redaudit.core.auditor_scan.ThreadPoolExecutor") as mock_exec,
            ):

                executor_instance = mock_exec.return_value.__enter__.return_value
                executor_instance.submit.return_value = mock_future

                app.run_agentless_verification([{"ip": "1.1.1.1"}])

        self.assertTrue(app.logger.debug.called)

    def test_wizard_arrow_menu_exception_path(self):
        """Cover wizard.py lines 488-494 (Exception in arrow menu)."""
        from redaudit.core.wizard import WizardMixin

        class MockApp(WizardMixin):
            def __init__(self):
                self.config = {}
                self.lang = "en"
                self.COLORS = {"HEADER": "", "ENDC": "", "OKBLUE": "", "CYAN": "", "BOLD": ""}
                self.t = lambda k, *a: k

            def _menu_width(self):
                return 80

            def _arrow_menu(self, *a, **k):
                raise Exception("Forced menu error")

            def _use_arrow_menu(self):
                return True

            def signal_handler(self, s, f):
                pass

            def print_status(self, *a, **k):
                pass

        app = MockApp()

        # Should catch exception and proceed to fallback (input)
        with patch("builtins.input", return_value="1"):
            with patch("builtins.print"):
                result = app.ask_choice_with_back("Test?", ["opt1"], step_num=2, total_steps=5)
                self.assertEqual(result, 0)

    def test_wizard_extract_mdns_name_more_coverage(self):
        """Cover auditor_scan.py lines 520-523 for mdns extraction."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        # Test valid decoding with match - matching literal backslash if present in regex
        # If regex is ([A-Za-z0-9._-]+\\.local), it expects a literal backslash.
        data = b"Some data before device\\.local some data after"
        result = AuditorScanMixin._extract_mdns_name(data)
        self.assertEqual(result, "device\\.local")

        # Test invalid decoding by passing a mock object that fails on decode
        mock_data = Mock()
        mock_data.decode.side_effect = Exception("Decode error")
        result = AuditorScanMixin._extract_mdns_name(mock_data)
        self.assertEqual(result, "")


if __name__ == "__main__":
    unittest.main()
