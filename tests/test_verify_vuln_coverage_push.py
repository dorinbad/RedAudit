"""
Tests for verify_vuln.py edge cases and missing coverage lines.
Target: Push verify_vuln.py from 83% to 98%+ coverage.
"""

import pytest
from unittest.mock import patch, MagicMock


class TestExtractPathFromFinding:
    """Tests for extract_path_from_finding function."""

    def test_extract_path_empty_input(self):
        """Test empty/None input returns None (line 65-66)."""
        from redaudit.core.verify_vuln import extract_path_from_finding

        assert extract_path_from_finding("") is None
        assert extract_path_from_finding(None) is None

    def test_extract_path_simple_pattern(self):
        """Test pattern 1: + /path: description (line 69-71)."""
        from redaudit.core.verify_vuln import extract_path_from_finding

        finding = "+ /backup.tar: This file may contain sensitive data"
        result = extract_path_from_finding(finding)

        assert result == "/backup.tar"

    def test_extract_path_osvdb_pattern(self):
        """Test pattern 2: OSVDB-XXXX: /path (lines 74-76)."""
        from redaudit.core.verify_vuln import extract_path_from_finding

        finding = "OSVDB-12345: /admin/.htpasswd found on server"
        result = extract_path_from_finding(finding)

        assert result == "/admin/.htpasswd"

    def test_extract_path_generic_pattern(self):
        """Test pattern 3: any path-like string (lines 79-81)."""
        from redaudit.core.verify_vuln import extract_path_from_finding

        finding = "Found sensitive file at /config/database.config readable"
        result = extract_path_from_finding(finding)

        assert result == "/config/database.config"

    def test_extract_path_no_match(self):
        """Test returns None when no path found (line 83)."""
        from redaudit.core.verify_vuln import extract_path_from_finding

        finding = "This finding has no path information"
        result = extract_path_from_finding(finding)

        assert result is None


class TestIsSensitiveFile:
    """Tests for is_sensitive_file function."""

    def test_is_sensitive_file_tar(self):
        """Test .tar is sensitive."""
        from redaudit.core.verify_vuln import is_sensitive_file

        assert is_sensitive_file("/backup.tar") is True

    def test_is_sensitive_file_pem(self):
        """Test .pem is sensitive."""
        from redaudit.core.verify_vuln import is_sensitive_file

        assert is_sensitive_file("/ssl/server.pem") is True

    def test_is_sensitive_file_not_sensitive(self):
        """Test non-sensitive extension."""
        from redaudit.core.verify_vuln import is_sensitive_file

        assert is_sensitive_file("/index.html") is False

    def test_is_sensitive_file_empty(self):
        """Test empty path returns False."""
        from redaudit.core.verify_vuln import is_sensitive_file

        assert is_sensitive_file("") is False


class TestVerifyContentType:
    """Tests for verify_content_type function (lines 101-151)."""

    def test_verify_content_type_success(self):
        """Test successful content type extraction."""
        from redaudit.core.verify_vuln import verify_content_type

        mock_result = MagicMock()
        mock_result.stdout = (
            "HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Length: 500\n"
        )

        with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
            mock_runner = MagicMock()
            mock_runner_class.return_value = mock_runner
            mock_runner.run.return_value = mock_result

            content_type, content_length = verify_content_type("http://test/api")

        assert content_type == "application/json"
        assert content_length == 500

    def test_verify_content_type_exception(self):
        """Test exception returns None, None (line 150-151)."""
        from redaudit.core.verify_vuln import verify_content_type

        with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
            mock_runner = MagicMock()
            mock_runner_class.return_value = mock_runner
            mock_runner.run.side_effect = Exception("curl failed")

            content_type, content_length = verify_content_type("http://test/api")

        assert content_type is None
        assert content_length is None

    def test_verify_content_type_no_curl_path(self):
        """Test when curl path not in extra_tools (line 115-117)."""
        from redaudit.core.verify_vuln import verify_content_type

        mock_result = MagicMock()
        mock_result.stdout = "HTTP/1.1 200 OK\n"

        with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
            mock_runner = MagicMock()
            mock_runner_class.return_value = mock_runner
            mock_runner.run.return_value = mock_result

            content_type, _ = verify_content_type("http://test/api", extra_tools={})

        # Should still work with default curl


class TestIsFalsePositiveByContentType:
    """Tests for is_false_positive_by_content_type function."""

    def test_false_positive_tar_got_json(self):
        """Test tar file returning JSON is false positive."""
        from redaudit.core.verify_vuln import is_false_positive_by_content_type

        result = is_false_positive_by_content_type(".tar", "application/json")
        assert result is True

    def test_not_false_positive_tar_got_octet(self):
        """Test tar file returning octet-stream is valid."""
        from redaudit.core.verify_vuln import is_false_positive_by_content_type

        result = is_false_positive_by_content_type(".tar", "application/octet-stream")
        assert result is False

    def test_not_false_positive_no_content_type(self):
        """Test returns False when no content type (line 167-168)."""
        from redaudit.core.verify_vuln import is_false_positive_by_content_type

        result = is_false_positive_by_content_type(".tar", None)
        assert result is False


class TestIsFalsePositiveBySize:
    """Tests for is_false_positive_by_size function."""

    def test_false_positive_small_tar(self):
        """Test small tar file is false positive."""
        from redaudit.core.verify_vuln import is_false_positive_by_size

        result = is_false_positive_by_size(".tar", 100)
        assert result is True

    def test_not_false_positive_large_tar(self):
        """Test large tar file is valid."""
        from redaudit.core.verify_vuln import is_false_positive_by_size

        result = is_false_positive_by_size(".tar", 10000)
        assert result is False

    def test_not_false_positive_no_size(self):
        """Test returns False when no size (line 191-192)."""
        from redaudit.core.verify_vuln import is_false_positive_by_size

        result = is_false_positive_by_size(".tar", None)
        assert result is False


class TestVerifyMagicBytes:
    """Tests for verify_magic_bytes function (lines 202-277)."""

    def test_verify_magic_ext_not_supported(self):
        """Test unsupported extension returns kept (line 235-236)."""
        from redaudit.core.verify_vuln import verify_magic_bytes

        is_valid, reason = verify_magic_bytes("http://test/file.txt", ".txt")

        assert is_valid is True
        assert "no_magic_check" in reason

    def test_verify_magic_exception(self):
        """Test exception returns kept (lines 276-277)."""
        from redaudit.core.verify_vuln import verify_magic_bytes

        with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
            mock_runner = MagicMock()
            mock_runner_class.return_value = mock_runner
            mock_runner.run.side_effect = Exception("Network error")

            is_valid, reason = verify_magic_bytes("http://test/backup.tar", ".tar")

        assert is_valid is True
        assert "error" in reason

    def test_verify_magic_html_detected(self):
        """Test HTML content detected as false positive (line 272-273)."""
        from redaudit.core.verify_vuln import verify_magic_bytes

        mock_result = MagicMock()
        # Need 257+ bytes for tar check, pad with zeros then add HTML signature area
        mock_result.stdout = b"<!DOCTYPE html>" + b"\x00" * 300 + b"<html>404 Not Found</html>"

        with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
            mock_runner = MagicMock()
            mock_runner_class.return_value = mock_runner
            mock_runner.run.return_value = mock_result

            is_valid, reason = verify_magic_bytes("http://test/backup.tar", ".tar")

        assert is_valid is False
        assert "html_or_json" in reason

    def test_verify_magic_json_detected(self):
        """Test JSON content detected as false positive (line 272)."""
        from redaudit.core.verify_vuln import verify_magic_bytes

        mock_result = MagicMock()
        mock_result.stdout = b'{"error": "not found"}'

        with patch("redaudit.core.verify_vuln.CommandRunner") as mock_runner_class:
            mock_runner = MagicMock()
            mock_runner_class.return_value = mock_runner
            mock_runner.run.return_value = mock_result

            is_valid, reason = verify_magic_bytes("http://test/backup.gz", ".gz")

        assert is_valid is False
        assert "html_or_json" in reason


class TestVerifyNiktoFinding:
    """Tests for verify_nikto_finding function (lines 280-330)."""

    def test_verify_no_path_extracted(self):
        """Test returns kept when no path (line 299-300)."""
        from redaudit.core.verify_vuln import verify_nikto_finding

        is_valid, reason = verify_nikto_finding("No path here", "http://test")

        assert is_valid is True
        assert "no_path" in reason

    def test_verify_not_sensitive_file(self):
        """Test returns kept for non-sensitive file (line 303-304)."""
        from redaudit.core.verify_vuln import verify_nikto_finding

        is_valid, reason = verify_nikto_finding("+ /index.html: test", "http://test")

        assert is_valid is True
        assert "not_sensitive" in reason


class TestFilterNiktoFalsePositives:
    """Tests for filter_nikto_false_positives function (lines 333-373)."""

    def test_filter_empty_findings(self):
        """Test empty findings returns empty list (line 350-351)."""
        from redaudit.core.verify_vuln import filter_nikto_false_positives

        result = filter_nikto_false_positives([], "http://test")
        assert result == []

    def test_filter_with_logger(self):
        """Test logging of filtered findings (lines 363-370)."""
        from redaudit.core.verify_vuln import filter_nikto_false_positives

        mock_logger = MagicMock()
        findings = ["+ /index.html: normal file"]

        with patch("redaudit.core.verify_vuln.verify_nikto_finding") as mock_verify:
            mock_verify.return_value = (True, "kept:verified")
            result = filter_nikto_false_positives(findings, "http://test", logger=mock_logger)

        assert len(result) == 1

    def test_filter_removes_false_positives(self):
        """Test false positives are removed from list."""
        from redaudit.core.verify_vuln import filter_nikto_false_positives

        findings = ["+ /backup.tar: sensitive", "+ /config.bak: sensitive"]

        with patch("redaudit.core.verify_vuln.verify_nikto_finding") as mock_verify:
            mock_verify.side_effect = [
                (True, "kept"),
                (False, "filtered"),
            ]
            result = filter_nikto_false_positives(findings, "http://test")

        assert len(result) == 1
