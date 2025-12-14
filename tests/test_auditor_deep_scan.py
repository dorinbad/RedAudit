#!/usr/bin/env python3
"""
RedAudit - Tests for deep scan heuristics
Ensures adaptive deep scan doesn't waste time on quiet hosts.
"""

import os
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.core.auditor import InteractiveNetworkAuditor


class _FakeHost(dict):
    def hostnames(self):
        return []

    def all_protocols(self):
        return ["tcp"]

    def state(self):
        return "up"


class _FakePortScanner:
    def __init__(self, ip: str, host: _FakeHost):
        self._ip = ip
        self._host = host

    def scan(self, *_args, **_kwargs):
        return None

    def all_hosts(self):
        return [self._ip]

    def __getitem__(self, ip):
        if ip != self._ip:
            raise KeyError(ip)
        return self._host


class TestAuditorDeepScanHeuristics(unittest.TestCase):
    def test_full_mode_skips_deep_scan_for_quiet_host(self):
        app = InteractiveNetworkAuditor()
        app.print_status = lambda *_args, **_kwargs: None
        app.config["scan_mode"] = "completo"
        app.config["deep_id_scan"] = True

        ip = "192.168.1.201"
        fake_host = _FakeHost(
            {
                "tcp": {},
                "addresses": {"mac": "AA:BB:CC:DD:EE:FF"},
                "vendor": {"AA:BB:CC:DD:EE:FF": "AVM"},
            }
        )
        nm = _FakePortScanner(ip=ip, host=fake_host)

        with patch("redaudit.core.auditor.nmap") as mock_nmap:
            mock_nmap.PortScanner.return_value = nm
            app.deep_scan_host = Mock(return_value={"strategy": "mock", "commands": []})

            result = app.scan_host_ports(ip)

        self.assertFalse(app.deep_scan_host.called)
        self.assertEqual(result.get("total_ports_found"), 0)
        self.assertEqual(result.get("deep_scan", {}).get("mac_address"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(result.get("deep_scan", {}).get("vendor"), "AVM")

    def test_normal_mode_still_triggers_deep_scan_for_small_port_hosts(self):
        app = InteractiveNetworkAuditor()
        app.print_status = lambda *_args, **_kwargs: None
        app.config["scan_mode"] = "normal"
        app.config["deep_id_scan"] = True

        ip = "192.168.1.10"
        fake_host = _FakeHost(
            {
                "tcp": {
                    80: {"name": "http", "product": "", "version": "", "extrainfo": "", "cpe": []},
                    443: {"name": "https", "product": "", "version": "", "extrainfo": "", "cpe": []},
                },
            }
        )
        nm = _FakePortScanner(ip=ip, host=fake_host)

        with patch("redaudit.core.auditor.nmap") as mock_nmap:
            mock_nmap.PortScanner.return_value = nm
            app.deep_scan_host = Mock(return_value={"strategy": "mock", "commands": []})

            _ = app.scan_host_ports(ip)

        self.assertTrue(app.deep_scan_host.called)


if __name__ == "__main__":
    unittest.main()

