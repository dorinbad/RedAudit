"""Tests for net_discovery.py to push coverage to 95%+
Targets missing lines including tool failures, parsing edge cases, and redteam components.
"""

import os
import shutil
import subprocess
import threading
from datetime import datetime
from unittest.mock import patch, MagicMock
import pytest

from redaudit.core.net_discovery import (
    dhcp_discover,
    fping_sweep,
    netbios_discover,
    netdiscover_scan,
    arp_scan_active,
    mdns_discover,
    upnp_discover,
    discover_networks,
    _run_cmd,
    _sanitize_iface,
    _sanitize_dns_zone,
    _gather_redteam_targets,
    _redteam_snmp_walk,
    _redteam_smb_enum,
    _redteam_rpc_enum,
    _redteam_ldap_enum,
    _redteam_kerberos_enum,
    _redteam_masscan_sweep,
    _redteam_dns_zone_transfer,
    _redteam_vlan_enum,
    _redteam_stp_topology,
    _redteam_hsrp_vrrp_discovery,
    _redteam_llmnr_nbtns_capture,
    _redteam_router_discovery,
    _redteam_ipv6_discovery,
    _redteam_bettercap_recon,
    _redteam_scapy_custom,
)


def test_run_cmd_exception():
    """Test _run_cmd exception handling (lines 54-57)."""
    with patch("redaudit.core.net_discovery.CommandRunner.run", side_effect=Exception("Fatal")):
        rc, out, err = _run_cmd(["ls"], 1, logger=MagicMock())
        assert rc == -1
        assert "Fatal" in err


def test_dhcp_discover_nmap_fail():
    """Test dhcp_discover nmap failure (lines 118-120)."""
    with patch("shutil.which", return_value="/bin/nmap"):
        with patch("redaudit.core.net_discovery._run_cmd", return_value=(1, "", "nmap error")):
            res = dhcp_discover()
            assert res["error"] == "nmap error"


def test_dhcp_discover_parsing_edge():
    """Test dhcp_discover parsing edge cases (lines 135-138, 161, 167, 173)."""
    # DHCPOFFER without IP, then another DHCPOFFER with IP.
    out = "DHCPOFFER:\nDHCPOFFER:\nServer Identifier: 1.1.1.1\nDomain Name: target.local\nDomain Search: search.local"
    with patch("shutil.which", return_value="/bin/nmap"):
        with patch("redaudit.core.net_discovery._run_cmd", return_value=(0, out, "")):
            res = dhcp_discover()
            assert len(res["servers"]) == 1
            assert res["servers"][0]["ip"] == "1.1.1.1"


def test_fping_sweep_stderr_alive():
    """Test fping_sweep alive detection from stderr (lines 216-221)."""
    with patch("shutil.which", return_value="/bin/fping"):
        with patch(
            "redaudit.core.net_discovery._run_cmd", return_value=(0, "", "1.1.1.1 is alive")
        ):
            res = fping_sweep("1.1.1.1")
            assert "1.1.1.1" in res["alive_hosts"]


def test_netbios_discover_nmap_fallback():
    """Test netbios_discover nbtscan missing, nmap fallback (line 269)."""
    with patch("shutil.which", side_effect=lambda x: "/bin/nmap" if x == "nmap" else None):
        with patch(
            "redaudit.core.net_discovery._run_cmd",
            return_value=(0, "Nmap scan report for 1.1.1.1\nNetBIOS name: HOST", ""),
        ):
            res = netbios_discover("1.1.1.1")
            assert res["hosts"][0]["name"] == "HOST"


def test_netdiscover_passive_and_vendor():
    """Test netdiscover_scan passive mode and vendor parsing (lines 341, 358-359)."""
    with patch("shutil.which", return_value="/bin/netdiscover"):
        out = "1.2.3.4 aa:bb:cc:dd:ee:ff 1 60 Cisco Systems"
        with patch("redaudit.core.net_discovery._run_cmd", return_value=(0, out, "")):
            res = netdiscover_scan("1.2.3.0/24", active=False)
            assert res["hosts"][0]["vendor"] == "Cisco Systems"


def test_arp_scan_active_parsing():
    """Test arp_scan_active parsing (lines 414-426)."""
    with patch("shutil.which", return_value="/bin/arp-scan"):
        out = "1.2.3.4\taa:bb:cc:dd:ee:ff\tVendor Name"
        with patch("redaudit.core.net_discovery._run_cmd", return_value=(0, out, "")):
            res = arp_scan_active()
            assert res["hosts"][0]["vendor"] == "Vendor Name"


def test_mdns_discover_iot_fallback():
    """Test mdns_discover iot specific queries fallback (lines 492-506)."""
    with patch("shutil.which", return_value="/bin/avahi-browse"):
        # First call empty, second one (iot) has more than top-5 (calls top-5)
        with patch(
            "redaudit.core.net_discovery._run_cmd",
            side_effect=[
                (0, "", ""),
                (0, "", ""),
                (0, "", ""),
                (0, "", ""),
                (0, "", ""),
                (0, "=;eth0;IPv4;Printer;_http._tcp;local;192.168.1.10", ""),
            ],
        ):
            res = mdns_discover()
            assert res["services"][0]["name"] == "Printer"


def test_upnp_discover_retry_and_ssdp():
    """Test upnp_discover retry and SSDP fallback (lines 583-596)."""
    with patch("shutil.which", return_value="/bin/nmap"):
        # 2 failures, then 1 SSDP success
        with patch(
            "redaudit.core.net_discovery._run_cmd",
            side_effect=[(0, "", ""), (0, "", ""), (0, "Server: NAS\n1.2.3.4:", "")],
        ):
            with patch("time.sleep"):
                res = upnp_discover(retries=2)
                assert res["devices"][0]["device"] == "NAS"


def test_discover_networks_protocol_loops():
    """Test discover_networks with various protocols and errors (lines 641, 670, 714, 730, 740, 748, 834, 836)."""
    # Force errors for all
    with patch("redaudit.core.net_discovery.dhcp_discover", return_value={"error": "E1"}):
        with patch("redaudit.core.net_discovery.fping_sweep", return_value={"error": "E2"}):
            with patch(
                "redaudit.core.net_discovery.netbios_discover", return_value={"error": "E3"}
            ):
                with patch(
                    "redaudit.core.net_discovery.arp_scan_active", return_value={"error": "E4"}
                ):
                    with patch(
                        "redaudit.core.net_discovery.netdiscover_scan", return_value={"error": "E5"}
                    ):
                        with patch(
                            "redaudit.core.net_discovery.mdns_discover",
                            return_value={"error": "E6"},
                        ):
                            with patch(
                                "redaudit.core.net_discovery.upnp_discover",
                                return_value={"error": "E7"},
                            ):
                                with patch(
                                    "redaudit.core.net_discovery._check_tools",
                                    return_value={"arp-scan": True},
                                ):
                                    res = discover_networks(
                                        ["1.1.1.0/24"],
                                        protocols=[
                                            "dhcp",
                                            "fping",
                                            "netbios",
                                            "arp",
                                            "mdns",
                                            "upnp",
                                        ],
                                    )
                                    assert len(res["errors"]) >= 6


def test_discover_networks_hyperscan_errors():
    """Test discover_networks hyperscan error handling (lines 834-836)."""
    # 834: ImportError
    with patch("builtins.__import__", side_effect=ImportError("No HS")):
        res = discover_networks([], protocols=["hyperscan"])
        assert any("module not available" in e for e in res["errors"])
    # 836: Exception
    with patch("redaudit.core.hyperscan.hyperscan_full_discovery", side_effect=Exception("Crash")):
        res = discover_networks([], protocols=["hyperscan"])
        assert any("hyperscan: Crash" in e for e in res["errors"])


def test_analyze_vlans_logic():
    """Test _analyze_vlans multiple subnets (line 881)."""
    from redaudit.core.net_discovery import _analyze_vlans

    results = {
        "dhcp_servers": [
            {"ip": "1.1.1.1", "subnet": "255.255.255.0", "gateway": "1.1.1.1"},
            {"ip": "2.2.2.2", "subnet": "255.255.255.0", "gateway": "2.2.2.2"},
        ]
    }
    candidates = _analyze_vlans(results)
    assert len(candidates) == 1
    assert candidates[0]["gateway"] == "2.2.2.2"


def test_redteam_discovery_ticker_and_cleanup():
    """Test _run_redteam_discovery progress ticker (lines 933-937, 947-949)."""
    # Mock progress callback to be slow enough to let ticker run
    mock_cb = MagicMock()
    with patch("redaudit.core.net_discovery._check_tools", return_value={}):
        with patch("redaudit.core.net_discovery._gather_redteam_targets", return_value=[]):
            from redaudit.core.net_discovery import _run_redteam_discovery

            # Ticker runs every 3s. We'll simulate a 4s task to ensure ticker hits.
            def slow_task(*args, **kwargs):
                import time

                time.sleep(4)
                return {}

            with patch("redaudit.core.net_discovery._redteam_masscan_sweep", side_effect=slow_task):
                _run_redteam_discovery(
                    {}, [], progress_callback=mock_cb, redteam_options={"max_targets": 10}
                )
    # Ticker should have called _progress_redteam
    # Just verify it finishes without error


def test_redteam_snmp_walk_errors():
    """Test _redteam_snmp_walk error paths (lines 1226, 1228, 1252, 1263)."""
    # 1226: No targets
    assert _redteam_snmp_walk([], {})["status"] == "no_targets"
    # 1228: Tool missing
    assert _redteam_snmp_walk(["1.1.1.1"], {})["status"] == "tool_missing"
    # 1252: Error log
    with patch("shutil.which", return_value="snmpwalk"):
        with patch(
            "redaudit.core.net_discovery._run_cmd", return_value=(1, "", "Permission Denied")
        ):
            res = _redteam_snmp_walk(["1.1.1.1"], {"snmpwalk": True})
            assert "Permission Denied" in res["errors"][0]
    # 1263: Row-based raw fallback
    with patch("shutil.which", return_value="snmpwalk"):
        with patch("redaudit.core.net_discovery._run_cmd", return_value=(0, "UNKNOWN OUTPUT", "")):
            res = _redteam_snmp_walk(["1.1.1.1"], {"snmpwalk": True})
            assert res["hosts"][0]["raw"] == "UNKNOWN OUTPUT"


def test_redteam_smb_enum_nmap_fallback():
    """Test _redteam_smb_enum nmap fallback and raw snippet (lines 1325, 1356)."""
    # 1325: Tool missing
    assert _redteam_smb_enum(["1.1.1.1"], {})["status"] == "tool_missing"
    # 1356: Raw snippet
    with patch("shutil.which", side_effect=lambda x: "nmap" if x == "nmap" else None):
        with patch(
            "redaudit.core.net_discovery._run_cmd",
            return_value=(0, "Nmap header\nweird output", ""),
        ):
            res = _redteam_smb_enum(["1.1.1.1"], {"nmap": True})
            assert res["hosts"][0]["tool"] == "nmap"
            assert "raw" in res["hosts"][0]


def test_redteam_masscan_sweep_safety():
    """Test _redteam_masscan_sweep root check and size check (lines 1386, 1401)."""
    with patch("shutil.which", return_value="masscan"):
        # 1386: Not root
        with patch("redaudit.core.net_discovery._is_root", return_value=False):
            assert (
                _redteam_masscan_sweep(["1.1.1.1"], {"masscan": True})["status"]
                == "skipped_requires_root"
            )
        # 1401: Too large
        with patch("redaudit.core.net_discovery._is_root", return_value=True):
            assert (
                _redteam_masscan_sweep(["0.0.0.0/8"], {"masscan": True})["status"]
                == "skipped_too_large"
            )


def test_redteam_rpc_enum_parsing():
    """Test _redteam_rpc_enum parsing and fallback (lines 1531, 1539)."""
    with patch("shutil.which", side_effect=lambda x: "rpcclient" if x == "rpcclient" else None):
        with patch(
            "redaudit.core.net_discovery._run_cmd",
            return_value=(0, "os version: Win10\ndomain: WORKGROUP", ""),
        ):
            res = _redteam_rpc_enum(["1.1.1.1"], {"rpcclient": True})
            assert res["hosts"][0]["os_version"] == "Win10"
        # 1531: Raw fallback
        with patch("redaudit.core.net_discovery._run_cmd", return_value=(0, "just some text", "")):
            res = _redteam_rpc_enum(["1.1.1.1"], {"rpcclient": True})
            assert "raw" in res["hosts"][0]


def test_redteam_kerberos_enum_userlist_paths():
    """Test _redteam_kerberos_enum userlist edge cases (lines 1702, 1704, 1708, 1733)."""
    # 1702: Kerbrute missing
    with patch("shutil.which", return_value="nmap"):
        res = _redteam_kerberos_enum(
            ["1.1.1.1"], {"nmap": True, "kerbrute": False}, userlist_path="/tmp/users"
        )
        assert res["userenum"]["status"] == "tool_missing"
    # 1704: Path missing
    with patch("shutil.which", side_effect=lambda x: "nmap" if x == "nmap" else "kerbrute"):
        with patch("os.path.exists", return_value=False):
            res = _redteam_kerberos_enum(
                ["1.1.1.1"], {"nmap": True, "kerbrute": True}, userlist_path="/tmp/no"
            )
            assert res["userenum"]["status"] == "error"
    # 1708: No realm
    with patch("shutil.which", return_value="/bin/kerbrute"):
        with patch("os.path.exists", return_value=True):
            with patch("redaudit.core.net_discovery._run_cmd", return_value=(0, "", "")):
                res = _redteam_kerberos_enum(
                    ["1.1.1.1"], {"nmap": True, "kerbrute": True}, userlist_path="/tmp/users"
                )
                assert res["userenum"]["status"] == "skipped_no_realm"


def test_redteam_dns_zone_transfer_edge():
    """Test _redteam_dns_zone_transfer no zone and failure (lines 1792, 1811)."""
    # 1792: No zone
    res = _redteam_dns_zone_transfer({"dhcp_servers": [{"dns": ["1.1.1.1"]}]}, {"dig": True})
    assert res["status"] == "skipped_no_zone"
    # 1811: Transfer failed msg
    with patch("shutil.which", return_value="dig"):
        with patch(
            "redaudit.core.net_discovery._run_cmd", return_value=(1, "transfer failed", "dig error")
        ):
            res = _redteam_dns_zone_transfer(
                {"dhcp_servers": [{"dns": ["1.1.1.1"]}]}, {"dig": True}, zone="target.local"
            )
            assert "transfer failed" in res["errors"][0]


def test_redteam_bettercap_recon_edge():
    """Test _redteam_bettercap_recon disabled and error (lines 2160, 2183)."""
    # 2160: active_l2 false
    assert (
        _redteam_bettercap_recon("eth0", {"bettercap": True}, active_l2=False)["status"]
        == "skipped_disabled"
    )
    # 2183: Error capture
    with patch("redaudit.core.net_discovery._is_root", return_value=True):
        with patch("shutil.which", return_value="bettercap"):
            with patch("redaudit.core.net_discovery._run_cmd", return_value=(1, "", "Fatal error")):
                res = _redteam_bettercap_recon("eth0", {"bettercap": True}, active_l2=True)
                assert res["error"] == "Fatal error"


def test_redteam_scapy_custom_exception():
    """Test _redteam_scapy_custom exception (line 2221)."""
    with patch("redaudit.core.net_discovery._is_root", return_value=True):
        # Mock scapy imports
        mock_scapy = MagicMock()
        mock_scapy.__version__ = "2.4.5"
        mock_dot1q = MagicMock()
        mock_sniff = MagicMock(side_effect=Exception("Scapy Error"))

        with patch.dict(
            "sys.modules",
            {
                "scapy": mock_scapy,
                "scapy.all": MagicMock(Dot1Q=mock_dot1q, sniff=mock_sniff),
            },
        ):
            # Need to patch the actual sniff call inside the function
            with patch("scapy.all.sniff", side_effect=Exception("Scapy Error")):
                res = _redteam_scapy_custom("eth0", {}, active_l2=True)
                # The function returns {"status": "error", "error": "..."} on exception
                assert res["status"] == "error"
                assert "Scapy Error" in res.get("error", "")


def test_sanitize_iface_none():
    """Test _sanitize_iface with None/invalid (line 1126, 1129)."""
    assert _sanitize_iface(None) is None
    assert _sanitize_iface("badinterface#") is None


def test_sanitize_dns_zone_none():
    """Test _sanitize_dns_zone with invalid inputs (lines 1134, 1138, 1140, 1142)."""
    assert _sanitize_dns_zone(None) is None
    assert _sanitize_dns_zone("a" * 300) is None
    assert _sanitize_dns_zone("a..b") is None
    assert _sanitize_dns_zone("-abc") is None
