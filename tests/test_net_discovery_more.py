#!/usr/bin/env python3
"""
Additional coverage for net_discovery utilities.
"""

from redaudit.core import net_discovery


def test_arp_scan_active_missing_tool(monkeypatch):
    monkeypatch.setattr(net_discovery.shutil, "which", lambda _name: None)
    result = net_discovery.arp_scan_active(target="192.168.1.0/24")
    assert result["error"] == "arp-scan not available"
    assert result["hosts"] == []


def test_arp_scan_active_parses_hosts(monkeypatch):
    def _which(name):
        return "/usr/bin/arp-scan" if name == "arp-scan" else None

    def _run_cmd(_cmd, _timeout, _logger):
        output = "192.168.1.1\td4:24:dd:07:7c:c5\tAVM GmbH\n"
        return 0, output, ""

    monkeypatch.setattr(net_discovery.shutil, "which", _which)
    monkeypatch.setattr(net_discovery, "_run_cmd", _run_cmd)

    result = net_discovery.arp_scan_active(target="192.168.1.0/24", interface="eth0")
    assert result["error"] is None
    assert result["hosts"][0]["ip"] == "192.168.1.1"
    assert result["hosts"][0]["vendor"] == "AVM GmbH"


def test_mdns_discover_avahi(monkeypatch):
    def _which(name):
        if name == "avahi-browse":
            return "/usr/bin/avahi-browse"
        return None

    def _run_cmd(_cmd, _timeout, _logger):
        output = "=;eth0;IPv4;MyDevice;_http._tcp;local;MyDevice;192.168.1.20;80;\n"
        return 0, output, ""

    monkeypatch.setattr(net_discovery.shutil, "which", _which)
    monkeypatch.setattr(net_discovery, "_run_cmd", _run_cmd)

    result = net_discovery.mdns_discover()
    assert result["services"]
    assert result["services"][0]["ip"] == "192.168.1.20"


def test_mdns_discover_avahi_specific(monkeypatch):
    def _which(name):
        if name == "avahi-browse":
            return "/usr/bin/avahi-browse"
        return None

    calls = {"count": 0}

    def _run_cmd(_cmd, _timeout, _logger):
        calls["count"] += 1
        if calls["count"] == 1:
            return 0, "", ""
        output = "=;eth0;IPv4;Device;_hap._tcp;local;Device;192.168.1.21;0;\n"
        return 0, output, ""

    monkeypatch.setattr(net_discovery.shutil, "which", _which)
    monkeypatch.setattr(net_discovery, "_run_cmd", _run_cmd)

    result = net_discovery.mdns_discover()
    assert result["services"]
    assert result["services"][0]["type"] == "_hap._tcp"


def test_mdns_discover_nmap_fallback(monkeypatch):
    def _which(name):
        if name == "nmap":
            return "/usr/bin/nmap"
        return None

    def _run_cmd(_cmd, _timeout, _logger):
        return 0, "service _tcp _http._tcp", ""

    monkeypatch.setattr(net_discovery.shutil, "which", _which)
    monkeypatch.setattr(net_discovery, "_run_cmd", _run_cmd)

    result = net_discovery.mdns_discover()
    assert result["services"][0]["type"] == "nmap_raw"


def test_mdns_discover_no_tools(monkeypatch):
    monkeypatch.setattr(net_discovery.shutil, "which", lambda _name: None)
    result = net_discovery.mdns_discover()
    assert result["error"] == "Neither avahi-browse nor nmap available"


def test_upnp_discover_parses_with_retry(monkeypatch):
    def _which(name):
        return "/usr/bin/nmap" if name == "nmap" else None

    calls = {"count": 0}

    def _run_cmd(_cmd, _timeout, _logger):
        calls["count"] += 1
        if calls["count"] == 1:
            return 0, "", ""
        output = "Server: Linux/3.14.0 UPnP/1.0\n192.168.1.1:1900\n"
        return 0, output, ""

    monkeypatch.setattr(net_discovery.shutil, "which", _which)
    monkeypatch.setattr(net_discovery, "_run_cmd", _run_cmd)
    monkeypatch.setattr(net_discovery.time, "sleep", lambda _s: None)

    result = net_discovery.upnp_discover(retries=2)
    assert result["devices"]
    assert result["devices"][0]["ip"] == "192.168.1.1"


def test_upnp_discover_ssdp_fallback(monkeypatch):
    def _which(name):
        return "/usr/bin/nmap" if name == "nmap" else None

    calls = {"count": 0}

    def _run_cmd(_cmd, _timeout, _logger):
        calls["count"] += 1
        if calls["count"] == 1:
            return 0, "", ""
        output = "Server: Test/1.0 UPnP/1.0\n192.168.1.2:1900\n"
        return 0, output, ""

    monkeypatch.setattr(net_discovery.shutil, "which", _which)
    monkeypatch.setattr(net_discovery, "_run_cmd", _run_cmd)

    result = net_discovery.upnp_discover(retries=1)
    assert result["devices"]
    assert result["devices"][0]["device"] == "Test/1.0 UPnP/1.0"


def test_upnp_discover_no_nmap(monkeypatch):
    monkeypatch.setattr(net_discovery.shutil, "which", lambda _name: None)
    result = net_discovery.upnp_discover()
    assert result["error"] == "nmap not available"
