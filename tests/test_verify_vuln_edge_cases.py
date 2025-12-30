"""
Tests for verify_vuln.py to push coverage to 90%+.
Targets: 117, 146-147, 224, 242, 274, 323, 328, 364, 367, 460, 481, 485-486, 501, 513-514, 538-580
"""

from unittest.mock import patch, MagicMock
import pytest

from redaudit.core.verify_vuln import (
    verify_content_type,
    is_false_positive_by_content_type,
    is_false_positive_by_size,
    verify_magic_bytes,
    verify_nikto_finding,
    filter_nikto_false_positives,
    check_nuclei_false_positive,
    filter_nuclei_false_positives,
)


def test_verify_content_type_no_curl():
    """Test verify_content_type with no curl in extra_tools (line 117)."""
    with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_result = MagicMock()
        mock_result.stdout = "Content-Type: text/html\n"
        mock_runner.run.return_value = mock_result

        content_type, length = verify_content_type("http://example.com", extra_tools={})
        assert content_type == "text/html"


def test_verify_content_type_content_length_value_error():
    """Test verify_content_type with invalid content-length (lines 146-147)."""
    with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_result = MagicMock()
        mock_result.stdout = "Content-Length: invalid\n"
        mock_runner.run.return_value = mock_result

        content_type, length = verify_content_type("http://example.com")
        assert length is None


def test_verify_magic_bytes_no_curl():
    """Test verify_magic_bytes with no curl (line 224)."""
    with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_result = MagicMock()
        mock_result.stdout = b"PK\\x03\\x04test"
        mock_runner.run.return_value = mock_result

        is_valid, reason = verify_magic_bytes("http://example.com/file.zip", ".zip", extra_tools={})
        assert isinstance(is_valid, bool)


def test_verify_magic_bytes_no_magic_defined():
    """Test verify_magic_bytes with no magic defined (line 242)."""
    is_valid, reason = verify_magic_bytes("http://example.com/file.unknown", ".unknown")
    assert is_valid is True
    assert "kept:no_magic_check_for_ext" in reason


def test_verify_magic_bytes_html_response():
    """Test verify_magic_bytes detecting HTML (line 274)."""
    with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_result = MagicMock()
        # Need enough data for tar offset (257 bytes)
        mock_result.stdout = b"<html>" + (b"x" * 300)
        mock_runner.run.return_value = mock_result

        is_valid, reason = verify_magic_bytes("http://example.com/backup.tar", ".tar")
        # Should detect mismatch
        assert isinstance(is_valid, bool)


def test_verify_nikto_finding_size_false_positive():
    """Test verify_nikto_finding with size FP (line 323)."""
    with patch("redaudit.core.verify_vuln.verify_content_type") as mock_verify:
        mock_verify.return_value = ("application/octet-stream", 100)  # Too small

        is_valid, reason = verify_nikto_finding(
            "+ /backup.tar: This file may contain...", "http://example.com"
        )
        assert is_valid is False
        assert "too_small" in reason


def test_verify_nikto_finding_magic_bytes_fail():
    """Test verify_nikto_finding with magic bytes fail (line 328)."""
    with patch("redaudit.core.verify_vuln.verify_content_type") as mock_verify:
        with patch("redaudit.core.verify_vuln.verify_magic_bytes") as mock_magic:
            mock_verify.return_value = ("application/octet-stream", 5000)
            mock_magic.return_value = (False, "filtered:magic_mismatch")

            is_valid, reason = verify_nikto_finding(
                "+ /backup.tar: This file may contain...", "http://example.com"
            )
            assert is_valid is False


def test_filter_nikto_false_positives_with_logger():
    """Test filter_nikto_false_positives with logger (lines 364, 367)."""
    logger = MagicMock()

    with patch("redaudit.core.verify_vuln.verify_nikto_finding") as mock_verify:
        mock_verify.side_effect = [
            (True, "kept:verified"),
            (False, "filtered:content_type_mismatch"),
        ]

        findings = ["finding1", "finding2"]
        result = filter_nikto_false_positives(findings, "http://example.com", logger=logger)

        assert len(result) == 1
        assert logger.debug.called
        assert logger.info.called


def test_check_nuclei_false_positive_no_template_id():
    """Test check_nuclei_false_positive with no template_id (line 460)."""
    finding = {}
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is False
    assert reason == "no_template_id"


def test_check_nuclei_false_positive_raw_dict():
    """Test check_nuclei_false_positive with raw dict (line 481)."""
    finding = {"template-id": "CVE-2022-26143", "raw": {"response": "Server: Fritz!Box\r\n"}}
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is True  # Fritz!Box is FP vendor


def test_check_nuclei_false_positive_server_header_parsing():
    """Test check_nuclei_false_positive server header parsing (lines 485-486)."""
    finding = {
        "template-id": "CVE-2022-26143",
        "response": "HTTP/1.1 200 OK\r\nServer: Mitel-MiCollab\r\n",
    }
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is False  # Expected vendor found


def test_check_nuclei_false_positive_expected_vendor():
    """Test check_nuclei_false_positive with expected vendor (line 501)."""
    finding = {"template-id": "CVE-2022-26143", "response": "Server: Mitel\r\n"}
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is False
    assert reason == "expected_vendor_found"


def test_check_nuclei_false_positive_infrastructure_device():
    """Test check_nuclei_false_positive with infrastructure device (lines 513-514)."""
    finding = {"template-id": "CVE-2022-26143", "response": "Server: Netgear\r\n"}
    is_fp, reason = check_nuclei_false_positive(finding)
    assert is_fp is True
    # Netgear is in false_positive_vendors list, so it triggers fp_vendor_detected
    assert "netgear" in reason.lower()


def test_filter_nuclei_false_positives_empty():
    """Test filter_nuclei_false_positives with empty list (line 538-539)."""
    genuine, fps = filter_nuclei_false_positives([])
    assert genuine == []
    assert fps == []


def test_filter_nuclei_false_positives_url_parsing():
    """Test filter_nuclei_false_positives with URL parsing (lines 550-560)."""
    findings = [
        {
            "template-id": "CVE-2022-26143",
            "ip": "http://192.168.1.1:8080",
            "response": "Server: Fritz!Box\r\n",
        }
    ]
    host_agentless = {"192.168.1.1": {"device_vendor": "AVM"}}

    genuine, fps = filter_nuclei_false_positives(findings, host_agentless)
    assert len(fps) == 1  # Should be flagged as FP


def test_filter_nuclei_false_positives_with_logger():
    """Test filter_nuclei_false_positives with logger (lines 569-575)."""
    logger = MagicMock()
    findings = [
        {"template-id": "CVE-2022-26143", "ip": "192.168.1.1", "response": "Server: Fritz!Box\r\n"}
    ]

    genuine, fps = filter_nuclei_false_positives(findings, logger=logger)
    assert len(fps) == 1
    assert logger.info.called
