import unittest
from unittest.mock import Mock, patch
from redaudit.core.net_discovery import (
    fping_sweep,
    netbios_discover,
    netdiscover_scan,
    arp_scan_active,
    mdns_discover,
    upnp_discover,
)

# We import exceptions if needed, but functions mostly capture them.


class TestCoverageAggressiveBatch11(unittest.TestCase):

    # --- net_discovery.py Tool Unavailability ---

    @patch("shutil.which", return_value=False)
    def test_fping_unavailable(self, mock_which):
        res = fping_sweep("1.1.1.1")
        self.assertIn("fping not available", res["error"])

    @patch("shutil.which", return_value=False)
    def test_netbios_unavailable(self, mock_which):
        # Both nbtscan and nmap unavailable
        res = netbios_discover("1.1.1.1")
        self.assertIn("Neither nbtscan nor nmap available", res["error"])

    @patch("shutil.which", return_value=False)
    def test_netdiscover_unavailable(self, mock_which):
        res = netdiscover_scan("1.1.1.1")
        self.assertIn("netdiscover not available", res["error"])

    @patch("shutil.which", return_value=False)
    def test_arp_scan_unavailable(self, mock_which):
        res = arp_scan_active("1.1.1.1")
        self.assertIn("arp-scan not available", res["error"])

    @patch("shutil.which", return_value=False)
    def test_mdns_unavailable(self, mock_which):
        res = mdns_discover()
        self.assertIn("Neither avahi-browse nor nmap available", res["error"])

    @patch("shutil.which", return_value=False)
    def test_upnp_unavailable(self, mock_which):
        res = upnp_discover()
        self.assertIn("nmap not available", res["error"])


if __name__ == "__main__":
    unittest.main()
