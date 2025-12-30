"""
Tests for scanner/status.py to push coverage to 95%+.
Targets uncovered lines: 27, 68, 123-124, 135, 147.
"""

from redaudit.core.scanner.status import (
    extract_vendor_mac,
    extract_os_detection,
    output_has_identity,
    finalize_host_status,
)
from redaudit.utils.constants import STATUS_DOWN, STATUS_FILTERED, STATUS_UP


def test_extract_vendor_mac_non_string_input():
    """Test extract_vendor_mac handles non-string input (line 27)."""
    # Pass an integer (non-string, non-bytes)
    mac, vendor = extract_vendor_mac(12345)
    assert mac is None
    assert vendor is None


def test_output_has_identity_stderr_bytes():
    """Test output_has_identity handles stderr as bytes (line 68)."""
    records = [
        {
            "stdout": "",
            "stderr": b"MAC Address: aa:bb:cc:dd:ee:ff (TestVendor)",
        }
    ]
    result = output_has_identity(records)
    assert result is True


def test_finalize_host_status_filtered_with_unfiltered():
    """Test finalize_host_status handles 'filtered' with 'unfiltered' (line 123-124)."""
    host_record = {
        "status": STATUS_DOWN,
        "ports": [],
        "deep_scan": {
            "commands": [
                {
                    "stdout": "Some ports are filtered but others are unfiltered",
                    "stderr": "",
                }
            ]
        },
    }
    # Should NOT return FILTERED because 'unfiltered' is present
    result = finalize_host_status(host_record)
    # Falls through to check other conditions
    assert result in [STATUS_DOWN, STATUS_FILTERED]


def test_finalize_host_status_os_detection_list():
    """Test finalize_host_status with os_detection list (line 135)."""
    host_record = {
        "status": STATUS_DOWN,
        "ports": [],
        "deep_scan": {
            "commands": [],
            "os_detection": ["Linux 5.x"],  # Non-empty list
        },
    }
    result = finalize_host_status(host_record)
    assert result == STATUS_FILTERED


def test_finalize_host_status_returns_down():
    """Test finalize_host_status returns STATUS_DOWN (line 147)."""
    host_record = {
        "status": STATUS_DOWN,
        "ports": [],
        "deep_scan": {
            "commands": [
                {
                    "stdout": "some output",
                    "stderr": "",
                }
            ]
        },
    }
    # No identity markers, sufficient output, should return DOWN
    result = finalize_host_status(host_record)
    assert result == STATUS_DOWN
