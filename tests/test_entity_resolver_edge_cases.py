"""Tests for entity_resolver.py to push coverage to 95%+
Targets lines: 218, 326, 367-376, 392, 417, 434, 436, 442, 444, 446, 452-454, 473, 526
"""

from redaudit.core.entity_resolver import (
    create_unified_asset,
    guess_asset_type,
    _derive_asset_name,
    reconcile_assets,
)
from unittest.mock import MagicMock


def test_create_unified_asset_vendor_fallback():
    """Test create_unified_asset vendor type fallback (line 218)."""
    host = {
        "ip": "1.2.3.4",
        "deep_scan": {
            "mac_address": "00:11:22:33:44:55",
            "vendor": "Some Strange Vendor Name That is Long",
        },
    }
    asset = create_unified_asset([host, host])
    assert asset["interfaces"][0]["type"] == "Some Strange Vendor "


def test_guess_asset_type_android_fallback():
    """Test guess_asset_type android without media signals (line 326)."""
    host = {"hostname": "android-device", "ports": []}
    assert guess_asset_type(host) == "mobile"


def test_guess_asset_type_agentless_types():
    """Test guess_asset_type with various agentless types (lines 367-376)."""
    # switch
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "switch"}}) == "switch"
    # printer
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "printer"}}) == "printer"
    # media
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "smart_tv"}}) == "media"
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "media"}}) == "media"
    # iot
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "iot"}}) == "iot"
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "smart_device"}}) == "iot"
    # server
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "nas"}}) == "server"
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "bmc"}}) == "server"
    assert guess_asset_type({"agentless_fingerprint": {"device_type": "hypervisor"}}) == "server"


def test_guess_asset_type_iot_hint():
    """Test guess_asset_type with iot hint (line 392)."""
    host = {"device_type_hints": ["iot"]}
    assert guess_asset_type(host) == "iot"


def test_guess_asset_type_switch_hint():
    """Test guess_asset_type with switch hint (line 417)."""
    host = {"agentless_fingerprint": {"http_title": "Managed Switch"}}
    assert guess_asset_type(host) == "switch"


def test_guess_asset_type_os_fingerprints():
    """Test guess_asset_type with OS patterns (lines 434-436)."""
    assert guess_asset_type({"os_detected": "Android 10"}) == "mobile"
    assert guess_asset_type({"os_detected": "iOS 14"}) == "mobile"
    assert guess_asset_type({"os_detected": "iPhone OS"}) == "mobile"


def test_guess_asset_type_vendor_patterns():
    """Test guess_asset_type with vendor patterns (lines 442-446)."""
    assert guess_asset_type({"deep_scan": {"vendor": "Apple Inc."}}) == "workstation"
    assert guess_asset_type({"deep_scan": {"vendor": "Tuya Smart"}}) == "iot"
    assert guess_asset_type({"deep_scan": {"vendor": "Google LLC"}}) == "smart_device"


def test_guess_asset_type_port_patterns():
    """Test guess_asset_type with port patterns (lines 452-454)."""
    # 80/443 with <= 3 ports -> iot
    assert guess_asset_type({"ports": [{"port": 80}]}) == "iot"
    # 80/443 with > 3 ports -> server
    assert (
        guess_asset_type({"ports": [{"port": 80}, {"port": 443}, {"port": 22}, {"port": 21}]})
        == "server"
    )


def test_derive_asset_name_no_vendor():
    """Test _derive_asset_name with title but no vendor (line 473)."""
    host = {"agentless_fingerprint": {"http_title": "Some Title"}}
    assert _derive_asset_name(host) == "Some Title"


def test_reconcile_assets_logging():
    """Test reconcile_assets with logger (line 526)."""
    host1 = {"ip": "1.2.3.4", "hostname": "host-a"}
    host2 = {"ip": "1.2.3.5", "hostname": "host-a"}  # Same fingerprint
    logger = MagicMock()
    unified = reconcile_assets([host1, host2], logger=logger)
    assert len(unified) == 1
    logger.info.assert_called()
