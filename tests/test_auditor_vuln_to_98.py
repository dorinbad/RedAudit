import pytest
from unittest.mock import MagicMock, patch, ANY
from redaudit.core.auditor_vuln import AuditorVulnMixin
from concurrent.futures import Future


class MockAuditor(AuditorVulnMixin):
    def __init__(self):
        self.results = {"vulnerabilities": []}
        self.extra_tools = {}
        self.config = {"scan_mode": "normal", "dry_run": False, "threads": 4}
        self.logger = MagicMock()
        self.current_phase = ""
        self.interrupted = False

    def print_status(self, msg, level, force=False, update_activity=True):
        pass

    def t(self, key, *args):
        return f"{key}:{args}"

    def _set_ui_detail(self, msg):
        pass

    def _get_ui_detail(self):
        return "detail"

    def _progress_ui(self):
        return MagicMock()  # Context manager

    def _progress_columns(self, **kwargs):
        return []

    def _progress_console(self):
        return MagicMock()

    def _format_eta(self, seconds):
        return f"{seconds}s"


@pytest.fixture
def auditor():
    return MockAuditor()


# -------------------------------------------------------------------------
# Test _parse_url_target
# -------------------------------------------------------------------------


def test_parse_url_target_basics(auditor):
    # Valid full URL
    host, port, scheme = auditor._parse_url_target("https://example.com:8443")
    assert host == "example.com"
    assert port == 8443
    assert scheme == "https"

    # Host:Port (no scheme)
    host, port, scheme = auditor._parse_url_target("192.168.1.1:8080")
    assert host == "192.168.1.1"
    assert port == 8080
    assert scheme == ""

    # Just Host
    host, port, scheme = auditor._parse_url_target("example.com")
    assert host == "example.com"
    assert port == 0
    assert scheme == ""

    # Scheme implied ports
    host, port, scheme = auditor._parse_url_target("https://example.com")
    assert host == "example.com"
    assert port == 443
    assert scheme == "https"

    host, port, scheme = auditor._parse_url_target("http://example.com")
    assert port == 80


def test_parse_url_target_edge_cases(auditor):
    # Invalid types
    assert auditor._parse_url_target(None) == ("", 0, "")
    assert auditor._parse_url_target(123) == ("", 0, "")

    # Empty/Whitespace
    assert auditor._parse_url_target("   ") == ("", 0, "")

    # Bad port
    host, port, scheme = auditor._parse_url_target("example.com:invalid")
    assert host == "example.com"
    assert port == 0

    # Exception simulation (mocking urlparse side effect if useful, but hard here due to internal import)
    # Just standard invalid URLs
    # "http://" with no host might return empty host
    host, port, scheme = auditor._parse_url_target("http://")
    # urlparse("http://") -> netloc='', scheme='http'
    assert host == ""


# -------------------------------------------------------------------------
# Test _merge_nuclei_findings
# -------------------------------------------------------------------------


def test_merge_nuclei_findings_empty(auditor):
    assert auditor._merge_nuclei_findings([]) == 0


def test_merge_nuclei_findings_integration(auditor):
    # Setup existing vulnerabilities
    auditor.results["vulnerabilities"] = [
        {"host": "192.168.1.10", "vulnerabilities": []},
        "invalid_entry_ignore",  # Should be ignored
    ]

    findings = [
        # Match existing host
        {
            "matched_at": "https://192.168.1.10:443/vuln",
            "template_id": "cve-2021-1234",
            "severity": "critical",
            "host": "192.168.1.10",
        },
        # New host
        {"matched_at": "http://10.0.0.1:80", "name": "exposure", "host": "10.0.0.1"},
        # Invalid finding
        "not_a_dict",
    ]

    count = auditor._merge_nuclei_findings(findings)
    assert count == 2

    # Check existing host updated
    # We must filter our manual check carefully as we inserted junk
    host_entry = next(
        h
        for h in auditor.results["vulnerabilities"]
        if isinstance(h, dict) and h.get("host") == "192.168.1.10"
    )
    assert len(host_entry["vulnerabilities"]) == 1
    v = host_entry["vulnerabilities"][0]
    assert v["template_id"] == "cve-2021-1234"
    assert v["port"] == 443
    assert v["scheme"] == "https"

    # Check new host added
    new_host = next(
        h
        for h in auditor.results["vulnerabilities"]
        if isinstance(h, dict) and h.get("host") == "10.0.0.1"
    )
    assert len(new_host["vulnerabilities"]) == 1


def test_merge_nuclei_findings_fallbacks(auditor):
    # Test fallback logic for name and host
    findings = [
        {
            "template_id": "test-id",
            # No matched_at, use host
            "host": "example.com:8080",
        }
    ]
    auditor._merge_nuclei_findings(findings)
    entry = auditor.results["vulnerabilities"][0]
    assert entry["host"] == "example.com"
    assert entry["vulnerabilities"][0]["port"] == 8080


# -------------------------------------------------------------------------
# Test _estimate_vuln_budget_s
# -------------------------------------------------------------------------


def test_estimate_budget(auditor):
    # Empty
    assert auditor._estimate_vuln_budget_s({}) == 0.0

    host_info = {"ports": [{"service": "http", "port": 80}, {"service": "https", "port": 443}]}

    # Basic
    budget = auditor._estimate_vuln_budget_s(host_info)
    # http=15, tls+https=10 -> 25.0
    assert budget >= 25.0

    # With tools and full mode
    auditor.extra_tools = {"whatweb": "bin", "nikto": "bin", "testssl.sh": "bin"}
    auditor.config["scan_mode"] = "completo"

    budget2 = auditor._estimate_vuln_budget_s(host_info)
    # Base 25 + whatweb(30) + nikto(150 in full) + testssl(90 in full) = ~295
    assert budget2 > 200.0

    # Robustness check for ports with no 'service' key or invalid port number
    bad_host = {"ports": [{"port": None}, {"port": "invalid"}]}
    assert auditor._estimate_vuln_budget_s(bad_host) >= 5.0  # Min budget


# -------------------------------------------------------------------------
# Test scan_vulnerabilities_web
# -------------------------------------------------------------------------


@patch("redaudit.core.auditor_vuln.http_enrichment")
@patch("redaudit.core.auditor_vuln.tls_enrichment")
def test_scan_web_basic(mock_tls, mock_http, auditor):
    mock_http.return_value = {"http_title": "Test"}
    mock_tls.return_value = {"tls_version": "1.3"}

    host_info = {
        "ip": "1.2.3.4",
        "ports": [
            {"port": 80, "service": "http", "is_web_service": True},
            {"port": 22, "service": "ssh", "is_web_service": False},  # Should be ignored
        ],
    }

    res = auditor.scan_vulnerabilities_web(host_info)
    assert res["host"] == "1.2.3.4"
    assert len(res["vulnerabilities"]) == 1
    assert res["vulnerabilities"][0]["port"] == 80


@patch("redaudit.core.auditor_vuln.http_enrichment")
@patch("redaudit.core.auditor_vuln.tls_enrichment")
@patch("redaudit.core.auditor_vuln.ssl_deep_analysis")
@patch("redaudit.core.auditor_vuln.CommandRunner")
def test_scan_web_full_tools(MockRunner, mock_ssl, mock_tls, mock_http, auditor):
    # Setup full scan
    auditor.config["scan_mode"] = "completo"
    auditor.extra_tools = {
        "whatweb": "/bin/whatweb",
        "nikto": "/bin/nikto",
        "testssl.sh": "/bin/testssl",
    }

    # Mock return values
    mock_http.return_value = {}
    mock_tls.return_value = {}
    mock_ssl.return_value = {"vulnerabilities": ["Heartbleed"]}  # Triggers warning log

    # Mock CommandRunner for WhatWeb and Nikto
    instance = MockRunner.return_value
    # whatweb call first, then nikto

    def side_effect_run(cmd, **kwargs):
        res = MagicMock()
        res.timed_out = False
        res.stdout = ""
        res.stderr = ""

        if "whatweb" in cmd[0]:
            res.stdout = "WhatWeb Report"
        elif "nikto" in cmd[0]:
            res.stdout = "+ /config.php: Found sensitive file\n+ /admin: Admin interface"

        return res

    instance.run.side_effect = side_effect_run

    # Mock smart check filter for Nikto
    with patch("redaudit.core.verify_vuln.filter_nikto_false_positives") as mock_filter:
        mock_filter.return_value = ["/admin: Admin interface"]  # One filtered out

        host_info = {
            "ip": "10.0.0.1",
            "ports": [{"port": 443, "service": "https", "is_web_service": True}],
        }

        res = auditor.scan_vulnerabilities_web(host_info)

        # Verify TestSSL called
        mock_ssl.assert_called()
        # Verify Whatweb result mapped
        vuln = res["vulnerabilities"][0]
        assert "WhatWeb Report" in vuln["whatweb"]
        # Verify Nikto filtered
        assert len(vuln["nikto_findings"]) == 1
        assert "nikto_filtered_count" in vuln


# Exception handling test
@patch("redaudit.core.auditor_vuln.http_enrichment")
@patch("redaudit.core.auditor_vuln.CommandRunner")
def test_scan_web_exceptions(MockRunner, mock_http, auditor):
    auditor.extra_tools = {"whatweb": "bin"}
    # Mock runner raising exception
    MockRunner.return_value.run.side_effect = Exception("Boom")
    # Make sure finding has > 2 fields so it is added
    mock_http.return_value = {"server": "Apache"}

    host_info = {
        "ip": "1.2.3.4",
        "ports": [{"port": 80, "service": "http", "is_web_service": True}],
    }

    # Should not crash
    res = auditor.scan_vulnerabilities_web(host_info)
    assert res is not None
    assert len(res["vulnerabilities"]) == 1
    # finding created but whatweb field missing


# -------------------------------------------------------------------------
# Exception handling for Nikto
# -------------------------------------------------------------------------
@patch("redaudit.core.auditor_vuln.CommandRunner")
def test_scan_nikto_exception(MockRunner, auditor):
    auditor.config["scan_mode"] = "completo"
    auditor.extra_tools = {"nikto": "bin"}

    instance = MockRunner.return_value
    # Run loop: Whatweb (if present) then Nikto. We only enabled Nikto.
    instance.run.side_effect = Exception("Nikto Failed")

    host_info = {
        "ip": "1.2.3.4",
        "ports": [{"port": 80, "service": "http", "is_web_service": True}],
    }

    # logs exception but doesn't crash
    res = auditor.scan_vulnerabilities_web(host_info)
    # No findings added
    assert res is None


def test_scan_web_no_ports(auditor):
    host_info = {"ip": "1.2.3.4", "ports": [{"port": 22}]}
    assert auditor.scan_vulnerabilities_web(host_info) is None


# -------------------------------------------------------------------------
# Test scan_vulnerabilities_concurrent EXTRA CASES
# -------------------------------------------------------------------------


@patch("redaudit.core.auditor_vuln.ThreadPoolExecutor")
def test_scan_concurrent_rich_success(MockExecutor, auditor):
    # Mock rich present
    import sys
    import types

    if "rich.progress" not in sys.modules:
        m = types.ModuleType("rich.progress")
        m.Progress = MagicMock()
        sys.modules["rich.progress"] = m
        sys.modules["rich"] = types.ModuleType("rich")
        sys.modules["rich"].progress = m

    # Setup rich mock
    with patch("rich.progress.Progress") as MockProgress:
        host1 = {"ip": "10.0.0.1", "web_ports_count": 1, "ports": [{"port": 80, "service": "http"}]}

        # Executor context manager setup
        executor = MockExecutor.return_value.__enter__.return_value

        # Create Futures
        f1 = Future()
        f1.set_result({"host": "10.0.0.1", "vulnerabilities": [{"id": 1}]})

        # We need to simulate submit calls returning our futures
        executor.submit.return_value = f1

        # Mock wait to return Done
        with patch("redaudit.core.auditor_vuln.wait") as mock_wait:
            mock_wait.return_value = ({f1}, set())
            auditor.scan_vulnerabilities_concurrent([host1])

        # Check results accumulated
        assert len(auditor.results["vulnerabilities"]) >= 1
        assert auditor.results["vulnerabilities"][-1]["host"] == "10.0.0.1"


@patch("redaudit.core.auditor_vuln.ThreadPoolExecutor")
def test_scan_concurrent_rich_interrupted(MockExecutor, auditor):
    # Mock rich present
    import sys

    if "rich.progress" not in sys.modules:
        sys.modules["rich.progress"] = MagicMock()

    with patch("rich.progress.Progress") as MockProgress:
        host1 = {"ip": "1.1.1.1", "web_ports_count": 1}
        executor = MockExecutor.return_value.__enter__.return_value

        f1 = Future()
        # Don't set result yet

        executor.submit.return_value = f1

        # We need to hook into wait() or the loop.
        # The loop runs while pending is not empty.
        # It calls wait().
        # We can make wait() set interrupted = True on the auditor

        def side_effect_wait(pending, **kwargs):
            auditor.interrupted = True
            return set(), pending  # Nothing done

        with patch("redaudit.core.auditor_vuln.wait", side_effect=side_effect_wait):
            auditor.scan_vulnerabilities_concurrent([host1])

        # Verify f1 was cancelled
        assert f1.cancelled()


@patch("redaudit.core.auditor_vuln.ThreadPoolExecutor")
def test_scan_concurrent_rich_worker_exception(MockExecutor, auditor):
    # Rich path
    import sys

    types = __import__("types")
    if "rich.progress" not in sys.modules:
        sys.modules["rich.progress"] = MagicMock()

    with patch("rich.progress.Progress"):
        host1 = {"ip": "1.1.1.1", "web_ports_count": 1}
        executor = MockExecutor.return_value.__enter__.return_value

        f1 = Future()
        f1.set_exception(ValueError("Worker Crash"))
        executor.submit.return_value = f1

        # Should catch and log error
        with patch("redaudit.core.auditor_vuln.wait") as mock_wait:
            mock_wait.return_value = ({f1}, set())
            auditor.scan_vulnerabilities_concurrent([host1])

        auditor.logger.error.assert_called()


@patch("redaudit.core.auditor_vuln.ThreadPoolExecutor")
def test_scan_concurrent_fallback_success(MockExecutor, auditor):
    # No rich
    with patch.dict("sys.modules", {"rich.progress": None}):
        host1 = {"ip": "10.0.0.1", "web_ports_count": 1, "ports": []}

        executor = MockExecutor.return_value.__enter__.return_value
        f1 = Future()
        f1.set_result({"host": "10.0.0.1", "vulnerabilities": [{"id": 1}]})
        executor.submit.return_value = f1

        auditor.scan_vulnerabilities_concurrent([host1])

        assert len(auditor.results["vulnerabilities"]) >= 1
        assert auditor.results["vulnerabilities"][-1]["host"] == "10.0.0.1"


@patch("redaudit.core.auditor_vuln.ThreadPoolExecutor")
def test_scan_concurrent_fallback_interrupted(MockExecutor, auditor):
    # No rich
    with patch.dict("sys.modules", {"rich.progress": None}):
        host1 = {"ip": "10.0.0.1", "web_ports_count": 1}
        executor = MockExecutor.return_value.__enter__.return_value
        f1 = Future()
        executor.submit.return_value = f1

        # as_completed yields futures. We want to interrupt inside the loop.
        # Logic: for fut in as_completed(futures): if interrupted break

        def iter_side_effect(futures):
            auditor.interrupted = True
            yield f1

        with patch("redaudit.core.auditor_vuln.as_completed", side_effect=iter_side_effect):
            auditor.scan_vulnerabilities_concurrent([host1])

        assert f1.cancelled()


def test_merge_nuclei_findings_no_host(auditor):
    # Both matched_at and host missing/empty
    findings = [{"name": "orphaned", "matched_at": "", "host": ""}]
    count = auditor._merge_nuclei_findings(findings)
    assert count == 0

    # matched_at empty, host valid
    findings = [{"name": "valid", "matched_at": "", "host": "valid.com"}]
    count = auditor._merge_nuclei_findings(findings)
    assert count == 1
    assert auditor.results["vulnerabilities"][-1]["host"] == "valid.com"


# Test fallback when rich not available
@patch("redaudit.core.auditor_vuln.ThreadPoolExecutor")
def test_scan_concurrent_no_rich(MockExecutor, auditor):
    # Force ImportError for rich
    with patch.dict("sys.modules", {"rich.progress": None}):
        host1 = {"ip": "1.1.1.1", "web_ports_count": 1, "ports": []}

        executor = MockExecutor.return_value.__enter__.return_value
        f1 = Future()
        f1.set_exception(ValueError("Worker Failed"))
        executor.submit.return_value = f1

        auditor.scan_vulnerabilities_concurrent([host1])
        # Should catch exception and log it, not crash
        # Results should be empty as it failed
        assert len(auditor.results["vulnerabilities"]) == 0
