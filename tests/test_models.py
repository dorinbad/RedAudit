"""
Tests for RedAudit Core Data Models.
"""

import pytest
from redaudit.core.models import Host, Service, Vulnerability


def test_host_initialization():
    """Test Host dataclass initialization and defaults."""
    h = Host(ip="192.168.1.1")
    assert h.ip == "192.168.1.1"
    assert h.mac_address == ""
    assert h.services == []
    assert h.status == "up"


def test_host_mac_alias():
    """Test backward compatibility alias for mac address."""
    h = Host(ip="10.0.0.1", mac_address="AA:BB:CC:DD:EE:FF")
    assert h.mac_address == "AA:BB:CC:DD:EE:FF"
    assert h.mac == "AA:BB:CC:DD:EE:FF"  # Alias check


def test_host_serialization():
    """Test Host to_dict serialization."""
    h = Host(ip="10.0.0.1", mac_address="00:11:22:33:44:55", hostname="test-box")
    data = h.to_dict()
    assert data["ip"] == "10.0.0.1"
    assert data["mac_address"] == "00:11:22:33:44:55"
    assert data["mac"] == "00:11:22:33:44:55"  # Should maintain both keys
    assert data["hostname"] == "test-box"


def test_service_defaults():
    """Test Service dataclass defaults."""
    s = Service(port=80)
    assert s.port == 80
    assert s.protocol == "tcp"
    assert s.state == "open"
    assert not s.is_encrypted


def test_service_encryption_detection():
    """Test is_encrypted logic."""
    s1 = Service(port=443, name="https", tunnel="ssl")
    assert s1.is_encrypted

    s2 = Service(port=3389, name="rdp")
    assert s2.is_encrypted

    s3 = Service(port=80, name="http")
    assert not s3.is_encrypted


def test_vulnerability_initialization():
    """Test Vulnerability dataclass."""
    v = Vulnerability(title="Weak Password", severity="High")
    assert v.title == "Weak Password"
    assert v.severity == "High"
    assert v.cvss_score == 0.0


def test_host_collections():
    """Test adding services and vulnerabilities to host."""
    h = Host(ip="192.168.1.5")
    s = Service(port=22, name="ssh")
    v = Vulnerability(title="Old SSH", severity="Low")

    h.add_service(s)
    h.add_vulnerability(v)

    assert len(h.services) == 1
    assert h.services[0].name == "ssh"
    assert len(h.vulnerabilities) == 1
    assert h.vulnerabilities[0].title == "Old SSH"
