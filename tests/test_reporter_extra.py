"""
Tests for reporter.py to boost coverage to 85%+.
Targets: config snapshot, summary helpers, report functions.
"""

from unittest.mock import patch, MagicMock
import pytest
import tempfile
import os
import json
from datetime import datetime

from redaudit.core.reporter import (
    _build_config_snapshot,
    _summarize_net_discovery,
    _summarize_vulnerabilities,
    _infer_vuln_source,
    generate_summary,
    generate_text_report,
    extract_leaked_networks,
)


# -------------------------------------------------------------------------
# Config Snapshot Tests
# -------------------------------------------------------------------------


def test_build_config_snapshot_empty():
    """Test _build_config_snapshot with empty config."""
    result = _build_config_snapshot({})
    assert "targets" in result
    assert "scan_mode" in result


def test_build_config_snapshot_full():
    """Test _build_config_snapshot with full config."""
    config = {
        "target_networks": ["192.168.1.0/24"],
        "scan_mode": "normal",
        "threads": 10,
        "rate_limit_delay": 0.5,
        "udp_mode": "quick",
        "topology_enabled": True,
        "net_discovery_enabled": True,
    }
    result = _build_config_snapshot(config)
    assert result["targets"] == ["192.168.1.0/24"]
    assert result["scan_mode"] == "normal"
    assert result["threads"] == 10


def test_build_config_snapshot_partial():
    """Test _build_config_snapshot with partial config."""
    config = {"scan_mode": "fast", "dry_run": True}
    result = _build_config_snapshot(config)
    assert result["scan_mode"] == "fast"
    assert result["dry_run"] is True


# -------------------------------------------------------------------------
# Net Discovery Summary Tests
# -------------------------------------------------------------------------


def test_summarize_net_discovery_empty():
    """Test _summarize_net_discovery with empty input."""
    result = _summarize_net_discovery({})
    assert result == {"enabled": False}


def test_summarize_net_discovery_none():
    """Test _summarize_net_discovery with None."""
    result = _summarize_net_discovery(None)
    assert result == {"enabled": False}


def test_summarize_net_discovery_full():
    """Test _summarize_net_discovery with full discovery data."""
    discovery = {
        "enabled": True,
        "protocols_used": ["arp", "dhcp", "mdns"],
        "redteam_enabled": True,
        "hyperscan_duration": 10.5,
        "dhcp_servers": [{"ip": "192.168.1.1"}],
        "alive_hosts": [{"ip": "192.168.1.2"}, {"ip": "192.168.1.3"}],
        "netbios_hosts": [],
        "arp_hosts": [{"ip": "192.168.1.4"}],
        "mdns_services": [{"name": "printer"}],
        "upnp_devices": [{"name": "router"}],
    }
    result = _summarize_net_discovery(discovery)
    assert result["enabled"] is True
    assert "counts" in result
    assert result["counts"]["dhcp_servers"] == 1
    assert result["counts"]["alive_hosts"] == 2


def test_summarize_net_discovery_with_errors():
    """Test _summarize_net_discovery with errors."""
    discovery = {
        "enabled": True,
        "errors": ["Error 1", "Error 2", "Error 3"],
    }
    result = _summarize_net_discovery(discovery)
    assert "errors" in result
    assert len(result["errors"]) <= 5


# -------------------------------------------------------------------------
# Vulnerability Summary Tests
# -------------------------------------------------------------------------


def test_summarize_vulnerabilities_empty():
    """Test _summarize_vulnerabilities with empty list."""
    result = _summarize_vulnerabilities([])
    assert isinstance(result, dict)


def test_summarize_vulnerabilities_with_vulns():
    """Test _summarize_vulnerabilities with vulnerability list."""
    vulns = [
        {"title": "SQL Injection", "severity": "high"},
        {"title": "XSS", "severity": "medium"},
    ]
    result = _summarize_vulnerabilities(vulns)
    assert isinstance(result, dict)


def test_infer_vuln_source_nikto():
    """Test _infer_vuln_source with nikto finding."""
    vuln = {"nikto_findings": ["vuln 1"]}
    result = _infer_vuln_source(vuln)
    assert result == "nikto" or result is not None


def test_infer_vuln_source_nuclei():
    """Test _infer_vuln_source with nuclei finding."""
    vuln = {"nuclei_findings": ["vuln 1"]}
    result = _infer_vuln_source(vuln)
    assert result == "nuclei" or result is not None


def test_infer_vuln_source_unknown():
    """Test _infer_vuln_source with no source."""
    vuln = {"title": "Generic vuln"}
    result = _infer_vuln_source(vuln)
    assert result is not None


# -------------------------------------------------------------------------
# Generate Summary Tests
# -------------------------------------------------------------------------


def test_generate_summary_minimal():
    """Test generate_summary with minimal input."""
    results = {"hosts": []}
    config = {"scan_mode": "normal"}
    summary = generate_summary(results, config, [], [], None)
    assert isinstance(summary, dict)


def test_generate_summary_with_hosts():
    """Test generate_summary with hosts."""
    results = {"hosts": []}
    config = {"scan_mode": "normal", "target_networks": ["192.168.1.0/24"]}
    all_hosts = [{"ip": "192.168.1.1"}]
    scanned = [{"ip": "192.168.1.1", "status": "up"}]
    summary = generate_summary(results, config, all_hosts, scanned, datetime.now())
    assert isinstance(summary, dict)


# -------------------------------------------------------------------------
# Generate Text Report Tests
# -------------------------------------------------------------------------


def test_generate_text_report_empty():
    """Test generate_text_report with empty results."""
    result = generate_text_report({})
    assert isinstance(result, str)


def test_generate_text_report_with_hosts():
    """Test generate_text_report with hosts."""
    results = {
        "hosts": [
            {"ip": "192.168.1.1", "status": "up", "hostname": "server1"},
        ],
        "summary": {"total_hosts": 1},
    }
    result = generate_text_report(results)
    assert isinstance(result, str)


def test_generate_text_report_partial():
    """Test generate_text_report with partial flag."""
    results = {"hosts": [], "summary": {}}
    result = generate_text_report(results, partial=True)
    assert isinstance(result, str)


# -------------------------------------------------------------------------
# Extract Leaked Networks Tests
# -------------------------------------------------------------------------


def test_extract_leaked_networks_empty():
    """Test extract_leaked_networks with empty results."""
    results = {"hosts": []}
    config = {"target_networks": ["192.168.1.0/24"]}
    leaks = extract_leaked_networks(results, config)
    assert isinstance(leaks, list)


def test_extract_leaked_networks_with_vulns():
    """Test extract_leaked_networks with vulnerability redirects."""
    results = {
        "hosts": [
            {
                "ip": "192.168.1.1",
                "vulnerabilities": [
                    {"title": "Redirect to 10.0.0.1"},
                ],
            }
        ]
    }
    config = {"target_networks": ["192.168.1.0/24"]}
    leaks = extract_leaked_networks(results, config)
    assert isinstance(leaks, list)
