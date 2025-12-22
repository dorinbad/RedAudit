#!/usr/bin/env python3
"""
RedAudit - Tests for auditor scanning helpers.
"""

from redaudit.core.auditor import InteractiveNetworkAuditor


def test_parse_host_timeout_s():
    app = InteractiveNetworkAuditor()
    assert app._parse_host_timeout_s("--host-timeout 30s") == 30.0
    assert app._parse_host_timeout_s("--host-timeout 200ms") == 0.2
    assert app._parse_host_timeout_s("--host-timeout 5m") == 300.0
    assert app._parse_host_timeout_s("nmap -sV") is None


def test_extract_nmap_xml():
    app = InteractiveNetworkAuditor()
    raw = "junk<?xml version='1.0'?><nmaprun><host></host></nmaprun>tail"
    assert app._extract_nmap_xml(raw) == "<nmaprun><host></host></nmaprun>"
    assert app._extract_nmap_xml("no xml here") == "no xml here"
