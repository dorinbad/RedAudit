"""Tests for agentless_verify.py to push coverage to 95%+
Targets parsers for SMB, RDP, LDAP, SSH, and HTTP outputs.
"""

from typing import Dict, Any
from unittest.mock import patch, MagicMock
import pytest
from redaudit.core.agentless_verify import (
    AgentlessProbeTarget,
    select_agentless_probe_targets,
    parse_smb_nmap,
    parse_ldap_rootdse,
    parse_rdp_ntlm_info,
    parse_ssh_hostkeys,
    parse_http_probe,
    _fingerprint_device_from_http,
    summarize_agentless_fingerprint,
    probe_agentless_services,
    _decode_text,
)


def test_decode_text_edge_cases():
    """Test _decode_text with various types (lines 102-106)."""
    assert _decode_text("test") == "test"
    assert _decode_text(b"test") == "test"
    assert _decode_text(None) == ""
    assert _decode_text(123) == "123"


def test_select_probe_targets_edge():
    """Test select_agentless_probe_targets with various host records (lines 47-85)."""
    hosts = [
        {"ip": "1.1.1.1", "ports": [{"port": 445, "service": "microsoft-ds"}]},  # SMB
        {"ip": "2.2.2.2", "ports": [{"port": 3389, "service": "ms-wbt-server"}]},  # RDP
        {"ip": "3.3.3.3", "ports": [{"port": 389, "service": "ldap"}]},  # LDAP
        {"ip": "4.4.4.4", "ports": [{"port": 2222, "service": "ssh"}]},  # Custom SSH
        {"ip": "5.5.5.5", "ports": [{"port": 80, "service": "http"}]},  # HTTP
    ]
    targets = select_agentless_probe_targets(hosts)
    assert len(targets) == 5
    assert targets[0].smb is True
    assert targets[1].rdp is True
    assert targets[2].ldap is True
    assert 2222 in targets[3].ssh_ports
    assert 80 in targets[4].http_ports


def test_parse_smb_nmap_edge():
    """Test parse_smb_nmap with various outputs (lines 141-176)."""
    text = "OS: Windows 10\nComputer name: WIN10-PRO\nDomain name: WORKGROUP\nmessage signing enabled but not required\nSMBv1: true"
    res = parse_smb_nmap(text)
    assert res["os"] == "Windows 10"
    assert res["computer_name"] == "WIN10-PRO"
    assert res["domain"] == "WORKGROUP"
    assert res["smb_signing_enabled"] is True
    assert res["smb_signing_required"] is False
    assert res["smbv1_detected"] is True

    # 161 and 164 paths
    assert parse_smb_nmap("message signing enabled and required")["smb_signing_required"] is True
    assert parse_smb_nmap("message signing disabled")["smb_signing_enabled"] is False


def test_parse_ldap_rootdse_edge():
    """Test parse_ldap_rootdse with various outputs (lines 183-210)."""
    text = "dnsHostName: dc1.lab.local\ndefaultNamingContext: DC=lab,DC=local\nsupportedLDAPVersion: 2, 3"
    res = parse_ldap_rootdse(text)
    assert res["dnsHostName"] == "dc1.lab.local"
    assert res["defaultNamingContext"] == "DC=lab,DC=local"
    assert "3" in res["supportedLDAPVersion"]

    assert parse_ldap_rootdse("") == {}


def test_parse_rdp_ntlm_info_edge():
    """Test parse_rdp_ntlm_info with various outputs (lines 217-231)."""
    text = "NetBIOS_Domain_Name: LAB\nNetBIOS_Computer_Name: SRV-RDP"
    res = parse_rdp_ntlm_info(text)
    assert res["netbios_domain"] == "LAB"
    assert res["netbios_name"] == "SRV-RDP"

    assert parse_rdp_ntlm_info("") == {}


def test_parse_ssh_hostkeys_edge():
    """Test parse_ssh_hostkeys with various outputs (lines 238-252)."""
    text = "| ssh-rsa SHA256:abc... (RSA)\n| ecdsa-sha2-nistp256 MD5:123... (ECDSA)"
    res = parse_ssh_hostkeys(text)
    assert any("SHA256:abc" in k for k in res["hostkeys"])

    assert parse_ssh_hostkeys("") == {}


def test_parse_http_probe_edge():
    """Test parse_http_probe with various outputs (lines 260-287, 350-365)."""
    text = "http-title: Home Page\nhttp-server-header: Apache/2.4.41"
    res = parse_http_probe(text)
    assert res["title"] == "Home Page"
    assert res["server"] == "Apache/2.4.41"

    # 277 path: multi-line header
    text_multi = "http-server-header:\n  nginx/1.18.0"
    res = parse_http_probe(text_multi)
    assert res["server"] == "nginx/1.18.0"

    # Fingerprint check
    text_hik = "http-title: Hikvision Digital Technology\nhttp-server-header: App-Http-Server"
    res = parse_http_probe(text_hik)
    assert res["device_vendor"] == "Hikvision"

    assert parse_http_probe("") == {}


def test_summarize_fingerprint_edge():
    """Test summarize_agentless_fingerprint with partial results (lines 468-524)."""
    probe = {
        "smb": {"os": "Windows 7", "computer_name": "LEGACY"},
        "http": {"title": "Login", "device_type": "camera"},
        "ssh": {"hostkeys": ["ssh-ed25519 hash"]},
    }
    summary = summarize_agentless_fingerprint(probe)
    assert summary["os"] == "Windows 7"
    assert summary["computer_name"] == "LEGACY"
    assert summary["device_type"] == "camera"
    assert "ssh-ed25519" in summary["ssh_hostkeys"][0]


def test_probe_services_dry_run():
    """Test probe_agentless_services with dry run (lines 377-461)."""
    target = AgentlessProbeTarget(ip="1.1.1.1", smb=True, rdp=True)
    with patch("redaudit.core.agentless_verify._run_nmap_script", return_value=(0, "output", "")):
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            res = probe_agentless_services(target, dry_run=True)
            assert res["smb"]["returncode"] == 0
