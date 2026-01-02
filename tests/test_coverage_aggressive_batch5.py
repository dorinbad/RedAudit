"""Aggressive coverage push v5 - Targeting auditor_scan.py and wizard.py missing branches"""

import unittest
from unittest.mock import Mock, patch
import ipaddress
from redaudit.core.auditor_scan import AuditorScanMixin
from redaudit.core.wizard import WizardMixin


class TestAggressiveCoverageBatch5(unittest.TestCase):

    def setUp(self):
        class MockMixer(AuditorScanMixin):
            def __init__(self):
                self.config = {}
                self.results = {}
                self.COLORS = {"HEADER": "", "ENDC": "", "OKGREEN": "", "CYAN": "", "BOLD": ""}
                self.lang = "en"
                self.logger = Mock()

            def t(self, k, *a):
                return k

            def print_status(self, *a, **k):
                pass

            def ask_manual_network(self) -> str:
                return "10.0.0.0/24"

            def ask_choice(self, *a, **k):
                return 0

        self.mixer = MockMixer()

    def test_collect_discovery_hosts_exception_paths(self):
        """Cover auditor_scan.py lines 201-203 and 209-211 logic."""
        # Note: We need to mock ipaddress.ip_network/ip_address inside the method
        # OR provide inputs that trigger the catch.

        # Invalid network strings should trigger 'continue' (line 203)
        self.mixer.results["net_discovery"] = {"alive_hosts": ["1.1.1.1", "2.2.2.2"]}
        target_nets = ["invalid/net", "1.1.1.0/24"]

        # _collect_discovery_hosts
        # Line 202 is catch Exception for ipaddress.ip_network(str(net))
        result = self.mixer._collect_discovery_hosts(target_nets)
        self.assertEqual(result, ["1.1.1.1"])

        # Invalid IP strings should trigger 'continue' (line 211)
        self.mixer.results["net_discovery"] = {"alive_hosts": ["invalid-ip", "1.1.1.1"]}
        target_nets = ["1.1.1.0/24"]
        result = self.mixer._collect_discovery_hosts(target_nets)
        self.assertEqual(result, ["1.1.1.1"])

    def test_select_net_discovery_interface_edge_cases(self):
        """Cover auditor_scan.py lines 257-260, 268-271, 274-275."""
        self.mixer.config["target_networks"] = ["invalid-net", "192.168.1.0/24"]
        self.mixer.results["network_info"] = [
            {"interface": "eth1", "network": "fd00::/64"},
            {"interface": "eth2", "network": "192.168.1.0/24"},
        ]

        result = self.mixer._select_net_discovery_interface()
        self.assertEqual(result, "eth2")

    @patch("builtins.input")
    def test_ask_network_range_all_and_manual(self, mock_input):
        """Cover auditor_scan.py lines 232-247."""
        with patch("redaudit.core.auditor_scan.detect_all_networks") as mock_det:
            # Case 1: detect_all_networks returns nothing
            mock_det.return_value = []
            mock_input.return_value = "10.0.0.0/24"
            res = self.mixer.ask_network_range()
            self.assertEqual(res, ["10.0.0.0/24"])

            # Case 2: manual_entry
            mock_det.return_value = [
                {"network": "192.168.1.0/24", "interface": "eth0", "hosts_estimated": 10}
            ]
            with (
                patch.object(self.mixer, "ask_choice", return_value=1),
                patch.object(self.mixer, "ask_manual_network", return_value="172.16.0.0/16"),
            ):
                res = self.mixer.ask_network_range()
                self.assertEqual(res, ["172.16.0.0/16"])

    def test_wizard_fmt_helpers(self):
        """Cover wizard.py lines 551-561 via _show_defaults_summary."""

        class MockWizard(WizardMixin):
            def __init__(self):
                self.lang = "en"
                self.t = lambda k, *a: k
                self.print_status = Mock()

        wiz = MockWizard()
        # Case: None values (triggering fmt_targets list check and fmt_bool)
        wiz._show_defaults_summary(
            {"target_networks": None, "topology_enabled": None, "scan_mode": "test"}
        )
        calls = [str(c) for c in wiz.print_status.call_args_list]
        self.assertTrue(any(":-" in c.replace(" ", "") for c in calls))

    def test_compute_identity_score_branches(self):
        """Cover auditor_scan.py lines 412-556."""
        # 1. Base case: low score
        record = {"ip": "1.1.1.1"}
        score, factors = self.mixer._compute_identity_score(record)
        self.assertEqual(score, 0)

        # 2. Multiple signals and vendor logic
        record = {
            "hostname": "host.local",
            "ports": [{"product": "Apache", "cpe": "cpe:/a:apache"}],
            "deep_scan": {"vendor": "Apple Inc."},
            "os_detected": "Linux",
        }
        score, factors = self.mixer._compute_identity_score(record)
        self.assertGreaterEqual(score, 4)
        self.assertIn("hostname", factors)
        self.assertIn("service_version", factors)
        self.assertIn("mac_vendor", factors)
        self.assertIn("os_detected", factors)

        # 3. Test different vendors for branch coverage
        vendors = ["HP", "Philips", "Tuya", "Fritz", "LG"]
        for v in vendors:
            record["deep_scan"]["vendor"] = v
            self.mixer._compute_identity_score(record)

        # 4. Test hostname hints (mobile)
        record["hostname"] = "iPhone-of-Dorin"
        self.mixer._compute_identity_score(record)
        record["hostname"] = "Galaxy-S21"
        self.mixer._compute_identity_score(record)


if __name__ == "__main__":
    unittest.main()
