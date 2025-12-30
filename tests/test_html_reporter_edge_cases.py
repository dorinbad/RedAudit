"""Tests for html_reporter.py to push coverage to 95%+
Targets lines: 23, 46-48, 134, 214-221, 280
"""

from unittest.mock import patch, MagicMock
import os
import pytest

from redaudit.core.html_reporter import (
    _get_reverse_dns,
    get_template_env,
    _extract_finding_title,
    _translate_finding_title,
    prepare_report_data,
)


def test_get_reverse_dns_empty():
    """Test _get_reverse_dns with empty/invalid data (line 23-24)."""
    assert _get_reverse_dns({}) == ""
    assert _get_reverse_dns({"dns": {"reverse": [None]}}) == ""
    assert _get_reverse_dns({"dns": {"reverse": ["host.local."]}}) == "host.local"


def test_basename_filter_empty():
    """Test Jinja2 basename_filter with empty path (lines 46-48)."""
    env = get_template_env()
    basename_filter = env.filters["basename"]
    assert basename_filter("") == ""
    assert basename_filter(None) == ""
    assert basename_filter("/path/to/file.txt") == "file.txt"


def test_prepare_report_data_no_observations():
    """Test prepare_report_data when observations is not a list (line 134)."""
    results = {
        "vulnerabilities": [
            {
                "host": "1.2.3.4",
                "vulnerabilities": [
                    {
                        "severity": "high",
                        "parsed_observations": None,  # Should trigger line 134
                        "nikto_findings": None,
                    }
                ],
            }
        ]
    }
    data = prepare_report_data(results, {"target_networks": []})
    assert data["finding_table"][0]["observations"] == []


def test_extract_finding_title_evidence_parser_exception():
    """Test _extract_finding_title with evidence_parser exception (lines 214-221)."""
    vuln = {"parsed_observations": ["some observation"]}
    with patch(
        "redaudit.core.evidence_parser._derive_descriptive_title",
        side_effect=Exception("parse error"),
    ):
        title = _extract_finding_title(vuln)
        # Should fall back to port-based title if port exists, or URL
        assert "Service Finding" in title or "Finding" in title


def test_extract_finding_title_evidence_parser_none():
    """Test _extract_finding_title when evidence_parser returns None (lines 214-221)."""
    vuln = {"parsed_observations": ["some observation"]}
    with patch("redaudit.core.evidence_parser._derive_descriptive_title", return_value=None):
        title = _extract_finding_title(vuln)
        assert "Service Finding" in title or "Finding" in title


def test_translate_finding_title_fallback():
    """Test _translate_finding_title fallback (line 280)."""
    assert _translate_finding_title("Unknown Title", "es") == "Unknown Title"
    assert _translate_finding_title("Unknown Title", "en") == "Unknown Title"


def test_prepare_report_data_with_reverse_dns():
    """Support test for _get_reverse_dns coverage in context."""
    results = {"hosts": [{"ip": "1.2.3.4", "dns": {"reverse": ["myhost.local."]}}]}
    data = prepare_report_data(results, {})
    assert data["host_table"][0]["hostname"] == "myhost.local"
