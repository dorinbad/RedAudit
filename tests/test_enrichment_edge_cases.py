"""Tests for enrichment.py to push coverage to 95%+
Targets lines: 42-43, 68-69, 87, 99-100, 110, 122-124, 143, 155-156, 166, 178-180, 204-205, 220-221, 301, 330, 368-369, 392, 412, 431-433, 436, 451, 454, 472, 477, 519, 531-536, 555, 579, 604
"""

from redaudit.core.scanner.enrichment import (
    enrich_host_with_dns,
    enrich_host_with_whois,
    _fetch_http_headers,
    _fetch_http_body,
    http_enrichment,
    http_identity_probe,
    tls_enrichment,
    exploit_lookup,
    ssl_deep_analysis,
    banner_grab_fallback,
)
from unittest.mock import patch, MagicMock
import subprocess
import pytest


def test_enrich_host_with_dns_exception():
    """Test enrich_host_with_dns with exception (lines 42-43)."""
    with patch(
        "redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("dig failed")
    ):
        host = {"ip": "8.8.8.8"}
        enrich_host_with_dns(host, {"dig": "dig"})
        assert "reverse" not in host["dns"]


def test_enrich_host_with_whois_exception():
    """Test enrich_host_with_whois with exception (lines 68-69)."""
    with patch(
        "redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("whois failed")
    ):
        host = {"ip": "8.8.8.8"}
        enrich_host_with_whois(host, {"whois": "whois"})
        assert "whois_summary" not in host["dns"]


def test_fetch_http_headers_https_k():
    """Test _fetch_http_headers with https -k (line 87)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner_cls:
        _fetch_http_headers("https://target", {"curl": "curl"})
        args = mock_runner_cls.return_value.run.call_args[0][0]
        assert "-k" in args


def test_fetch_http_headers_curl_exception():
    """Test _fetch_http_headers curl exception (lines 99-100)."""
    with patch(
        "redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("curl error")
    ):
        assert _fetch_http_headers("http://t", {"curl": "curl"}) == ""


def test_fetch_http_headers_wget_https():
    """Test _fetch_http_headers wget https (line 110)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner_cls:
        _fetch_http_headers("https://target", {"wget": "wget"})
        args = mock_runner_cls.return_value.run.call_args[0][0]
        assert "--no-check-certificate" in args


def test_fetch_http_headers_wget_exception():
    """Test _fetch_http_headers wget exception (lines 122-124)."""
    with patch(
        "redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("wget error")
    ):
        assert _fetch_http_headers("http://t", {"wget": "wget"}) == ""


def test_fetch_http_body_https_k():
    """Test _fetch_http_body with https -k (line 143)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner_cls:
        _fetch_http_body("https://target", {"curl": "curl"})
        args = mock_runner_cls.return_value.run.call_args[0][0]
        assert "-k" in args


def test_fetch_http_body_curl_exception():
    """Test _fetch_http_body curl exception (lines 155-156)."""
    with patch(
        "redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("curl error")
    ):
        assert _fetch_http_body("http://t", {"curl": "curl"}) == ""


def test_fetch_http_body_wget_https():
    """Test _fetch_http_body wget https (line 166)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner_cls:
        _fetch_http_body("https://target", {"wget": "wget"})
        args = mock_runner_cls.return_value.run.call_args[0][0]
        assert "--no-check-certificate" in args


def test_fetch_http_body_wget_exception():
    """Test _fetch_http_body wget exception (lines 178-180)."""
    with patch(
        "redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("wget error")
    ):
        assert _fetch_http_body("http://t", {"wget": "wget"}) == ""


def test_http_enrichment_exceptions():
    """Test http_enrichment curl/wget exceptions (lines 204-205, 220-221)."""
    with patch("redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("error")):
        res = http_enrichment("http://t", {"curl": "curl", "wget": "wget"})
        assert res == {}


def test_http_identity_probe_invalid_ip():
    """Test http_identity_probe with invalid IP (line 301)."""
    assert http_identity_probe("invalid", {"curl": "curl"}) == {}


def test_http_identity_probe_fallback():
    """Test http_identity_probe fallback return (line 330)."""
    with patch("redaudit.core.scanner.enrichment._fetch_http_headers", return_value=""):
        with patch("redaudit.core.scanner.enrichment._fetch_http_body", return_value=""):
            assert http_identity_probe("1.2.3.4", {"curl": "curl"}) == {}


def test_tls_enrichment_exception():
    """Test tls_enrichment exception (lines 368-369)."""
    with patch("redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("ssl error")):
        assert tls_enrichment("1.2.3.4", 443, {"openssl": "openssl"}) == {}


def test_exploit_lookup_empty_params():
    """Test exploit_lookup with empty params (line 392)."""
    assert exploit_lookup(" ", " ", {"searchsploit": "s"}) == []


def test_exploit_lookup_empty_output():
    """Test exploit_lookup with empty output (line 412)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner:
        mock_runner.return_value.run.return_value = MagicMock(stdout="", returncode=0)
        assert exploit_lookup("ssh", "2.0", {"searchsploit": "s"}) == []


def test_exploit_lookup_timeout():
    """Test exploit_lookup timeout (lines 431-433)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner:
        mock_runner.return_value.run.side_effect = subprocess.TimeoutExpired(["s"], 10)
        assert exploit_lookup("ssh", "2.0", {"searchsploit": "s"}, logger=MagicMock()) == []


def test_exploit_lookup_exception():
    """Test exploit_lookup general exception (line 436)."""
    with patch(
        "redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("fatal error")
    ):
        assert exploit_lookup("ssh", "2.0", {"searchsploit": "s"}, logger=MagicMock()) == []


def test_ssl_deep_analysis_invalid_target():
    """Test ssl_deep_analysis invalid target/port (lines 451, 454)."""
    assert ssl_deep_analysis("invalid", 443, {"testssl.sh": "t"}) is None
    assert ssl_deep_analysis("1.2.3.4", -1, {"testssl.sh": "t"}) is None


def test_ssl_deep_analysis_timeout():
    """Test ssl_deep_analysis timeout (line 472)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner:
        mock_res = MagicMock()
        mock_res.timed_out = True
        mock_runner.return_value.run.return_value = mock_res
        assert (
            ssl_deep_analysis("1.2.3.4", 443, {"testssl.sh": "t"}, logger=MagicMock()) is not None
        )


def test_ssl_deep_analysis_empty_output():
    """Test ssl_deep_analysis empty output (line 477)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner:
        mock_runner.return_value.run.return_value = MagicMock(stdout="", stderr="", timed_out=False)
        assert ssl_deep_analysis("1.2.3.4", 443, {"testssl.sh": "t"}) is None


def test_ssl_deep_analysis_weak_ciphers_summary():
    """Test ssl_deep_analysis weak ciphers summary (line 519)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner:
        mock_runner.return_value.run.return_value = MagicMock(
            stdout="Weak cipher detected", timed_out=False
        )
        res = ssl_deep_analysis("1.2.3.4", 443, {"testssl.sh": "t"})
        assert "WARNING: 1 weak" in res["summary"]


def test_ssl_deep_analysis_fail_and_exception():
    """Test ssl_deep_analysis fail scenarios (lines 531-536)."""
    # Fail to find anything useful
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner:
        mock_runner.return_value.run.return_value = MagicMock(stdout="All OK", timed_out=False)
        assert ssl_deep_analysis("1.2.3.4", 443, {"testssl.sh": "t"}) is None
    # Exception
    with patch("redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("fail")):
        assert ssl_deep_analysis("1.2.3.4", 443, {"testssl.sh": "t"}, logger=MagicMock()) is None


def test_banner_grab_no_ports():
    """Test banner_grab_fallback no ports (line 555)."""
    assert banner_grab_fallback("1.2.3.4", []) == {}


def test_banner_grab_timeout():
    """Test banner_grab_fallback timeout (line 579)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner:
        mock_res = MagicMock()
        mock_res.timed_out = True
        mock_runner.return_value.run.return_value = mock_res
        assert banner_grab_fallback("1.2.3.4", [80], logger=MagicMock()) == {}


def test_banner_grab_exception():
    """Test banner_grab_fallback exception (line 604)."""
    with patch(
        "redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("nmap error")
    ):
        assert banner_grab_fallback("1.2.3.4", [80], logger=MagicMock()) == {}
