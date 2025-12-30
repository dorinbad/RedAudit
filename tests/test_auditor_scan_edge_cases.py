"""Tests for auditor_scan.py to push coverage to 95%+
Uses a mock class to test the AuditorScanMixin.
"""

import os
import shutil
import time
from unittest.mock import patch, MagicMock
import pytest
from redaudit.core.auditor_scan import AuditorScanMixin
import redaudit.core.auditor_scan as scan_mod
from redaudit.utils.constants import STATUS_DOWN, STATUS_NO_RESPONSE, UDP_SCAN_MODE_FULL


class MockAuditor(AuditorScanMixin):
    def __init__(self):
        self.results = {"hosts": []}
        self.config = {
            "output_dir": "/tmp",
            "scan_mode": "rapido",
            "deep_id_scan": True,
            "threads": 1,
        }
        self.extra_tools = {}
        self.logger = MagicMock()
        self.rate_limit_delay = 0.0
        self.interrupted = False
        self.lang = "en"
        self.COLORS = {
            "HEADER": "",
            "OKGREEN": "",
            "WARNING": "",
            "FAIL": "",
            "ENDC": "",
            "INFO": "",
        }
        self.current_phase = ""

    def t(self, key, *args):
        return f"{key}:{args}"

    def print_status(self, msg, color=None, force=False, update_activity=True):
        pass

    def ask_choice(self, prompt, options):
        return 0

    def ask_manual_network(self):
        return "1.1.1.1/32"

    def _progress_ui(self):
        class Dummy:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        return Dummy()

    def _progress_console(self):
        return MagicMock()

    def _progress_columns(self, **kwargs):
        return []

    def _set_ui_detail(self, detail):
        self._ui_detail = detail

    def _get_ui_detail(self):
        return getattr(self, "_ui_detail", "")

    def _touch_activity(self):
        pass

    def _coerce_text(self, val):
        return str(val or "")

    def _format_eta(self, s):
        return str(s)

    def _safe_text_column(self, *args, **kwargs):
        return MagicMock()


def test_check_dependencies_missing_nmap():
    """Test check_dependencies with missing nmap binary (lines 87-89)."""
    auditor = MockAuditor()
    with patch("shutil.which", return_value=None):
        assert auditor.check_dependencies() is False


def test_check_dependencies_missing_module():
    """Test check_dependencies with missing nmap python module (lines 95-97)."""
    auditor = MockAuditor()
    with patch("shutil.which", return_value="/usr/bin/nmap"):
        with patch("importlib.import_module", side_effect=ImportError("no nmap")):
            assert auditor.check_dependencies() is False


def test_check_dependencies_fallback_path():
    """Test check_dependencies with testssl.sh fallback path (lines 135-137)."""
    auditor = MockAuditor()
    with patch.object(
        scan_mod.shutil, "which", side_effect=lambda x: "/usr/bin/nmap" if x == "nmap" else None
    ):
        with patch("importlib.import_module", return_value=MagicMock()):
            with patch.object(scan_mod.os.path, "isfile", return_value=True):
                with patch.object(scan_mod.os, "access", return_value=True):
                    auditor.check_dependencies()
                    assert auditor.extra_tools.get("testssl.sh") is not None


def test_collect_discovery_hosts_filtering():
    """Test _collect_discovery_hosts with various sources and network filter (lines 172-209)."""
    auditor = MockAuditor()
    auditor.results["net_discovery"] = {
        "alive_hosts": ["1.1.1.1"],
        "arp_hosts": [{"ip": "1.1.1.2"}],
        "netbios_hosts": [{"ip": "1.1.1.3"}],
        "upnp_devices": [{"ip": "1.1.1.4"}],
        "mdns_services": [{"ip": "1.1.1.5"}],
        "dhcp_servers": [{"ip": "1.1.1.6"}],
        "hyperscan_tcp_hosts": {"1.1.1.7": {}},
    }
    # No filter
    hosts = auditor._collect_discovery_hosts([])
    assert len(hosts) == 7
    # With filter
    hosts = auditor._collect_discovery_hosts(["1.1.1.0/29"])
    assert "1.1.1.8" not in hosts


def test_ask_network_range_all_dedupe():
    """Test ask_network_range 'scan all' deduplication (lines 230-238)."""
    auditor = MockAuditor()
    nets = [
        {"interface": "eth0", "network": "10.0.0.0/24", "hosts_estimated": 10},
        {"interface": "eth1", "network": "10.0.0.0/24", "hosts_estimated": 10},
    ]
    with patch.object(auditor, "detect_all_networks", return_value=nets):
        with patch.object(
            auditor, "ask_choice", return_value=3
        ):  # Choice 3: scan_all (0:eth0, 1:eth1, 2:manual, 3:scan_all)
            res = auditor.ask_network_range()
            assert res == ["10.0.0.0/24"]  # Deduplicated


def test_select_net_discovery_interface_overlaps():
    """Test _select_net_discovery_interface with overlaps (lines 267-268)."""
    auditor = MockAuditor()
    auditor.config["target_networks"] = ["192.168.1.0/24"]
    auditor.results["network_info"] = [{"interface": "vlan10", "network": "192.168.1.0/24"}]
    assert auditor._select_net_discovery_interface() == "vlan10"


def test_run_nmap_xml_scan_parse_error():
    """Test _run_nmap_xml_scan with invalid XML (lines 444-448)."""
    auditor = MockAuditor()
    with patch("shutil.which", return_value="/bin/nmap"):
        with patch("redaudit.core.auditor_scan.nmap", MagicMock()) as mock_nmap_mod:
            with patch(
                "redaudit.core.auditor_scan.run_nmap_command",
                return_value={"stdout_full": "<nmaprun>XML</nmaprun>"},
            ):
                mock_nm = MagicMock()
                mock_nmap_mod.PortScanner.return_value = mock_nm
                # Force analyser failure (both spellings)
                mock_nm.analyse_nmap_xml_scan.side_effect = Exception("Parse Error")
                mock_nm.analyze_nmap_xml_scan.side_effect = Exception("Parse Error")
                auditor._coerce_text = MagicMock(return_value="<nmaprun>XML</nmaprun>")
                nm, err = auditor._run_nmap_xml_scan("1.1.1.1", "-p 80")
                assert "Parse Error" in err


def test_parse_host_timeout_units():
    """Test _parse_host_timeout_s with various units (lines 467-474)."""
    assert AuditorScanMixin._parse_host_timeout_s("--host-timeout 100ms") == 0.1
    assert AuditorScanMixin._parse_host_timeout_s("--host-timeout 10s") == 10.0
    assert AuditorScanMixin._parse_host_timeout_s("--host-timeout 1m") == 60.0
    assert AuditorScanMixin._parse_host_timeout_s("--host-timeout 1h") == 3600.0


def test_deep_scan_host_adaptive_paths():
    """Test deep_scan_host with various identity triggers and capture (lines 539-664)."""
    auditor = MockAuditor()
    auditor.config["udp_mode"] = UDP_SCAN_MODE_FULL
    with patch("redaudit.core.auditor_scan.start_background_capture", return_value={"id": 1}):
        with patch(
            "redaudit.core.auditor_scan.run_nmap_command",
            return_value={"stdout": "Nmap scan result"},
        ):
            with patch(
                "redaudit.core.auditor_scan.output_has_identity", side_effect=[False, False]
            ):
                with patch("redaudit.core.auditor_scan.run_udp_probe", return_value=[]):
                    with patch("redaudit.core.auditor_scan.get_neighbor_mac", return_value=None):
                        with patch(
                            "redaudit.core.auditor_scan.stop_background_capture",
                            return_value={"file": "cap.pcap"},
                        ):
                            res = auditor.deep_scan_host("1.1.1.1")
                            assert "udp_top_ports" in res


def test_scan_host_ports_failures():
    """Test scan_host_ports with nmap failure and deep scan fallback (lines 765, 793, 807)."""
    auditor = MockAuditor()
    # Case 1: nmap fails entirely
    with patch.object(auditor, "_run_nmap_xml_scan", return_value=(None, "Generic Error")):
        with patch("redaudit.core.auditor_scan.get_neighbor_mac", return_value="aa:bb:cc:dd:ee:ff"):
            res = auditor.scan_host_ports("1.2.3.4")
            assert res["status"] == STATUS_NO_RESPONSE
            assert res["deep_scan"]["mac_address"] == "aa:bb:cc:dd:ee:ff"

    # Case 2: host not in nmap results but deep scan finds it
    nm_mock = MagicMock()
    nm_mock.all_hosts.return_value = []
    with patch.object(auditor, "_run_nmap_xml_scan", return_value=(nm_mock, "")):
        with patch.object(auditor, "deep_scan_host", return_value={"os_detected": "Linux"}):
            res = auditor.scan_host_ports("5.6.7.8")
            assert res["os_detected"] == "Linux"


def test_scan_host_ports_identity_heuristics():
    """Test identity score and deep scan triggers (lines 1083-1111)."""
    auditor = MockAuditor()
    nm_mock = MagicMock()
    nm_mock.all_hosts.return_value = ["1.1.1.1"]
    data = MagicMock()
    data.all_protocols.return_value = ["tcp"]
    data.__getitem__.return_value = {80: {"name": "http", "product": "", "version": ""}}
    data.hostnames.return_value = [{"name": "webserver"}]
    data.state.return_value = "up"
    nm_mock.__getitem__.return_value = data

    with patch.object(auditor, "_run_nmap_xml_scan", return_value=(nm_mock, "")):
        with patch.object(auditor, "deep_scan_host", return_value={}) as mock_deep:
            # Low visibility host -> triggers deep scan
            res = auditor.scan_host_ports("1.1.1.1")
            assert mock_deep.called
            assert "low_visibility" in res["smart_scan"]["reasons"]
            assert "no_version_info" in res["smart_scan"]["reasons"]


def test_scan_hosts_concurrent_interruption():
    """Test scan_hosts_concurrent interruption (lines 1260-1263)."""
    auditor = MockAuditor()
    with patch("concurrent.futures.ThreadPoolExecutor.submit", return_value=MagicMock()):
        with patch("concurrent.futures.wait", side_effect=[(set(), {MagicMock()})]):
            auditor.interrupted = True
            res = auditor.scan_hosts_concurrent(["1.1.1.1"])
            assert len(res) == 0


def test_run_agentless_verification_opt_out():
    """Test run_agentless_verification opt-out (line 1346)."""
    auditor = MockAuditor()
    auditor.config["windows_verify_enabled"] = False
    auditor.run_agentless_verification([])
    assert "agentless_verify" not in auditor.results
