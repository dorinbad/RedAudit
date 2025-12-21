#!/usr/bin/env python3
"""
RedAudit - Tests for auditor vulnerability helpers.
"""

from unittest.mock import patch

from redaudit.core.auditor import InteractiveNetworkAuditor


def _make_app():
    app = InteractiveNetworkAuditor()
    app.print_status = lambda *_args, **_kwargs: None
    app._set_ui_detail = lambda *_args, **_kwargs: None
    app.logger = None
    return app


def test_parse_url_target():
    app = _make_app()
    assert app._parse_url_target(None) == ("", 0, "")
    assert app._parse_url_target("example.com:8443") == ("example.com", 8443, "")
    assert app._parse_url_target("https://example.com") == ("example.com", 443, "https")
    assert app._parse_url_target("http://example.com:8080/path") == (
        "example.com",
        8080,
        "http",
    )


def test_merge_nuclei_findings_creates_hosts():
    app = _make_app()
    app.results["vulnerabilities"] = [{"host": "10.0.0.1", "vulnerabilities": []}]

    findings = [
        {"matched_at": "http://10.0.0.1:80", "severity": "high", "template_id": "t1"},
        {"host": "10.0.0.2:443", "name": "n2"},
    ]
    merged = app._merge_nuclei_findings(findings)
    assert merged == 2

    vuln_hosts = {entry["host"] for entry in app.results["vulnerabilities"]}
    assert vuln_hosts == {"10.0.0.1", "10.0.0.2"}


def test_estimate_vuln_budget_s_full_mode():
    app = _make_app()
    app.config["scan_mode"] = "completo"
    app.extra_tools = {
        "whatweb": "/bin/whatweb",
        "nikto": "/bin/nikto",
        "testssl.sh": "/bin/testssl",
    }

    host_info = {
        "ports": [
            {"port": 80, "service": "http"},
            {"port": 443, "service": "ssl"},
        ]
    }

    assert app._estimate_vuln_budget_s(host_info) == 490.0
    assert app._estimate_vuln_budget_s({"ports": []}) == 0.0


def test_scan_vulnerabilities_web_basic_https():
    app = _make_app()
    app.config["scan_mode"] = "normal"
    app.extra_tools = {}

    host_info = {
        "ip": "10.0.0.3",
        "ports": [{"port": 443, "service": "https", "is_web_service": True}],
    }

    with patch("redaudit.core.auditor_vuln.http_enrichment", return_value={"http_status": 200}):
        with patch("redaudit.core.auditor_vuln.tls_enrichment", return_value={"tls": "ok"}):
            result = app.scan_vulnerabilities_web(host_info)

    assert result["host"] == "10.0.0.3"
    assert len(result["vulnerabilities"]) == 1
    finding = result["vulnerabilities"][0]
    assert finding["url"] == "https://10.0.0.3:443/"
    assert finding["http_status"] == 200
    assert finding["tls"] == "ok"
