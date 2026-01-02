import unittest
from unittest.mock import Mock, patch
from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.core.auditor_scan import AuditorScanMixin


class TestCoverageAggressiveBatch10(unittest.TestCase):
    def setUp(self):
        # Create a mock application that mixes in AuditorScanMixin
        class MockApp(AuditorScanMixin):
            def __init__(self):
                self.config = {}
                self.results = {}
                self.logger = Mock()
                self.t = lambda x, *args: x

        self.app = MockApp()

    @patch("redaudit.core.auditor_scan.get_vendor_with_fallback")
    def test_apply_net_discovery_identity_exceptions(self, mock_vendor):
        host = {"ip": "1.2.3.4", "hostname": ""}
        self.app.results = {
            "net_discovery": {
                "arp_hosts": [{"ip": "1.2.3.4", "mac": "AA:BB", "vendor": "Unknown Vendor"}]
            }
        }

        # Test 1: Vendor is unknown -> tries lookup -> lookup raises exception
        mock_vendor.side_effect = Exception("Lookup Failed")
        self.app._apply_net_discovery_identity(host)
        # Should not crash. deep_scan is created due to MAC, but vendor remains None?
        # If vendor was "Unknown Vendor", code sets it to None.
        # exception in fallback leaves it as None.
        # So deep_scan shouldn't have "device_vendor" set.
        deep = host.get("deep_scan")
        self.assertIsNotNone(deep)
        self.assertEqual(deep.get("mac_address"), "AA:BB")
        self.assertNotIn("device_vendor", deep)

    def test_extract_nmap_xml_edge_cases(self):
        from redaudit.core.auditor_scan import AuditorScanMixin

        # None
        self.assertEqual(AuditorScanMixin._extract_nmap_xml(None), "")
        # Empty
        self.assertEqual(AuditorScanMixin._extract_nmap_xml(""), "")
        # No xml start
        self.assertEqual(AuditorScanMixin._extract_nmap_xml("garbagenostart"), "garbagenostart")
        # Start but no end
        xml = "<nmaprun>content"
        self.assertEqual(AuditorScanMixin._extract_nmap_xml(xml), xml)
        # Full extraction
        xml = "junk<nmaprun>content</nmaprun>junk"
        self.assertEqual(AuditorScanMixin._extract_nmap_xml(xml), "<nmaprun>content</nmaprun>")
        # XML decl fallback - if <nmaprun> is present, it strips pre-amble
        xml = "<?xml version='1.0'?><nmaprun>content</nmaprun>"
        self.assertEqual(AuditorScanMixin._extract_nmap_xml(xml), "<nmaprun>content</nmaprun>")

    def test_smart_scan_deep_trigger_branches(self):
        # Method is _should_trigger_deep
        # 1. Many ports
        res, reasons = self.app._should_trigger_deep(
            total_ports=9,
            any_version=False,
            suspicious=False,
            device_type_hints=[],
            identity_score=5,
            identity_threshold=3,
        )
        self.assertTrue(res, f"Failed Case 1: Reasons={reasons}")
        self.assertIn("many_ports", reasons)
        self.assertIn("no_version_info", reasons)

        # 2. Suspicious
        res, reasons = self.app._should_trigger_deep(
            total_ports=1,
            any_version=True,
            suspicious=True,
            device_type_hints=[],
            identity_score=5,
            identity_threshold=3,
        )
        self.assertTrue(res)
        self.assertIn("suspicious_service", reasons)

        # 3. Router hint - MUST have weak identity to avoid override
        res, reasons = self.app._should_trigger_deep(
            total_ports=1,
            any_version=True,
            suspicious=False,
            device_type_hints=["router"],
            identity_score=2,
            identity_threshold=3,
        )
        self.assertTrue(res)
        self.assertIn("network_infrastructure", reasons)

        # 4. Identity Strong (explicit False trigger)
        res, reasons = self.app._should_trigger_deep(
            total_ports=5,
            any_version=True,
            suspicious=False,
            device_type_hints=[],
            identity_score=10,
            identity_threshold=3,
        )
        self.assertFalse(res)
        self.assertIn("identity_strong", reasons)

    def test_scan_mode_timeouts_coverage(self):
        # fast
        self.app.config["scan_mode"] = "fast"
        self.assertEqual(self.app._scan_mode_host_timeout_s(), 10.0)
        # full
        self.app.config["scan_mode"] = "full"
        self.assertEqual(self.app._scan_mode_host_timeout_s(), 300.0)
        # default
        self.app.config["scan_mode"] = "normal"
        self.assertEqual(self.app._scan_mode_host_timeout_s(), 60.0)

    def test_lookup_topology_fallback_coverage(self):
        # Empty inputs / no match
        self.app.results = {}
        self.assertEqual(self.app._lookup_topology_identity("1.1.1.1"), (None, None))

        # Valid topology but no match
        self.app.results = {
            "topology": {"interfaces": [{"arp": {"hosts": [{"ip": "2.2.2.2", "mac": "CC:DD"}]}}]}
        }
        self.assertEqual(self.app._lookup_topology_identity("1.1.1.1"), (None, None))

        # Match with unknown vendor (cleared to None)
        self.app.results["topology"]["interfaces"][0]["arp"]["hosts"].append(
            {"ip": "1.1.1.1", "mac": "EE:FF", "vendor": "Unknown"}
        )
        mac, vendor = self.app._lookup_topology_identity("1.1.1.1")
        self.assertEqual(mac, "EE:FF")
        self.assertIsNone(vendor)  # Filtered "Unknown"

    def test_prune_weak_identity_reasons_logic(self):
        # Lines 752-770
        # Exception path
        self.app._prune_weak_identity_reasons(None)

        # Empty reasons
        scan = {"reasons": []}
        self.app._prune_weak_identity_reasons(scan)

        # Exception during int conversion (e.g. score is None)
        scan = {"reasons": ["r1"], "identity_score": None}
        self.app._prune_weak_identity_reasons(scan)

        # Score < Threshold
        scan = {"reasons": ["r1"], "identity_score": 1, "identity_threshold": 3}
        self.app._prune_weak_identity_reasons(scan)
        self.assertEqual(scan["reasons"], ["r1"])

        # Score >= Threshold, prune "low_visibility"
        scan = {
            "reasons": ["low_visibility", "identity_weak", "other"],
            "identity_score": 5,
            "identity_threshold": 3,
        }
        self.app._prune_weak_identity_reasons(scan)
        self.assertEqual(scan["reasons"], ["other"])
        self.assertEqual(scan["escalation_reason"], "other")

    @patch("redaudit.core.auditor_scan.run_udp_probe")
    @patch("redaudit.core.auditor_scan.UDP_PRIORITY_PORTS", "53,invalid")
    def test_run_udp_priority_probe_config_exception(self, mock_probe):
        host = {"ip": "1.2.3.4"}
        mock_probe.return_value = []
        # "invalid" in UDP_PRIORITY_PORTS should trigger exception log
        self.app._run_udp_priority_probe(host)
        self.app.logger.debug.assert_called()  # Should log debug on exception


if __name__ == "__main__":
    unittest.main()
