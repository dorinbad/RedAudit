#!/usr/bin/env python3
"""
Additional coverage for NVD query/caching helpers.
"""

import builtins
import importlib
import json
import os
import time
from urllib.error import HTTPError
from unittest.mock import MagicMock

from redaudit.core import nvd


def test_get_api_key_from_env(monkeypatch):
    monkeypatch.setattr(nvd, "CONFIG_AVAILABLE", False)
    monkeypatch.setenv("NVD_API_KEY", "env-key")
    assert nvd.get_api_key_from_config() == "env-key"


def test_get_api_key_from_config_prefers_config(monkeypatch):
    monkeypatch.setattr(nvd, "CONFIG_AVAILABLE", True)
    monkeypatch.setattr(nvd, "config_get_nvd_api_key", lambda: "cfg-key")
    monkeypatch.setenv("NVD_API_KEY", "env-key")
    assert nvd.get_api_key_from_config() == "cfg-key"


def test_import_error_sets_config_unavailable(monkeypatch):
    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name == "redaudit.utils.config":
            raise ImportError("boom")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    reloaded = importlib.reload(nvd)
    assert reloaded.CONFIG_AVAILABLE is False

    monkeypatch.setattr(builtins, "__import__", real_import)
    importlib.reload(nvd)


def test_ensure_cache_dir_chmod_error(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "NVD_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(nvd.os, "chmod", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()))
    path = nvd.ensure_cache_dir()
    assert os.path.isdir(path)


def test_get_cached_result_expired(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "NVD_CACHE_DIR", str(tmp_path))
    cache_file = tmp_path / f"{nvd.get_cache_key('query')}.json"
    cache_file.write_text(json.dumps({"cves": ["x"]}), encoding="utf-8")

    old_time = time.time() - (nvd.NVD_CACHE_TTL + 10)
    os.utime(cache_file, (old_time, old_time))

    assert nvd.get_cached_result("query") is None
    assert not cache_file.exists()


def test_get_cached_result_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "NVD_CACHE_DIR", str(tmp_path))
    assert nvd.get_cached_result("missing") is None


def test_get_cached_result_invalid_json(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "NVD_CACHE_DIR", str(tmp_path))
    cache_file = tmp_path / f"{nvd.get_cache_key('query')}.json"
    cache_file.write_text("{bad json", encoding="utf-8")
    assert nvd.get_cached_result("query") is None


def test_save_to_cache_chmod_error(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "NVD_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(nvd.os, "chmod", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()))
    nvd.save_to_cache("query", {"cves": []})
    cache_file = tmp_path / f"{nvd.get_cache_key('query')}.json"
    assert cache_file.exists()


def test_save_to_cache_open_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "NVD_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(nvd, "ensure_cache_dir", lambda: str(tmp_path))
    monkeypatch.setattr(
        builtins, "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError())
    )
    nvd.save_to_cache("query", {"cves": []})


def test_query_nvd_uses_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "NVD_CACHE_DIR", str(tmp_path))
    nvd.save_to_cache("cached", {"cves": [{"cve_id": "CVE-1"}]})

    def _fail_urlopen(*_args, **_kwargs):
        raise AssertionError("urlopen should not be called for cache hits")

    monkeypatch.setattr(nvd, "urlopen", _fail_urlopen)
    cached = nvd.query_nvd(keyword="cached")
    assert cached == [{"cve_id": "CVE-1"}]


def test_query_nvd_no_params():
    assert nvd.query_nvd() == []


def test_query_nvd_cache_hit_logs(monkeypatch):
    logger = MagicMock()
    monkeypatch.setattr(
        nvd, "get_cached_result", lambda *_args, **_kwargs: {"cves": [{"cve_id": "C"}]}
    )
    result = nvd.query_nvd(keyword="apache", logger=logger)
    assert result == [{"cve_id": "C"}]
    assert logger.debug.called


def test_query_nvd_parses_response(monkeypatch):
    sample = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "published": "2024-01-01",
                    "descriptions": [{"lang": "en", "value": "Test description"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                }
            }
        ]
    }

    class _Response:
        status = 200

        def read(self):
            return json.dumps(sample).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(nvd, "get_cached_result", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(nvd, "save_to_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(nvd, "urlopen", lambda *_args, **_kwargs: _Response())

    result = nvd.query_nvd(keyword="apache", api_key=None, logger=None)
    assert result[0]["cve_id"] == "CVE-2024-0001"
    assert result[0]["cvss_score"] == 9.8
    assert result[0]["cvss_severity"] == "CRITICAL"


def test_query_nvd_parses_cvss_v2_and_no_english_desc(monkeypatch):
    sample = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0002",
                    "published": "2024-01-02",
                    "descriptions": [{"lang": "es", "value": "Descripcion"}],
                    "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]},
                }
            }
        ]
    }

    class _Response:
        status = 200

        def read(self):
            return json.dumps(sample).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(nvd, "get_cached_result", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(nvd, "save_to_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(nvd, "urlopen", lambda *_args, **_kwargs: _Response())

    result = nvd.query_nvd(cpe_name="cpe:2.3:a:vendor:prod:1.0:*:*:*:*:*:*:*", api_key="k")
    assert result[0]["cvss_score"] == 5.0
    assert result[0]["cvss_severity"] is None
    assert result[0]["description"] == ""


def test_query_nvd_handles_http_error(monkeypatch):
    def _raise_http(*_args, **_kwargs):
        raise HTTPError("url", 404, "not found", hdrs=None, fp=None)

    monkeypatch.setattr(nvd, "get_cached_result", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(nvd, "urlopen", _raise_http)
    monkeypatch.setattr(nvd.time, "sleep", lambda *_args, **_kwargs: None)

    result = nvd.query_nvd(keyword="apache", api_key=None, logger=None)
    assert result == []


def test_query_nvd_http_error_retry_then_success(monkeypatch):
    sample = {"vulnerabilities": []}

    class _Response:
        status = 200

        def read(self):
            return json.dumps(sample).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    http_error = HTTPError("url", 429, "rate", hdrs=None, fp=None)
    monkeypatch.setattr(nvd, "get_cached_result", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(nvd, "save_to_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(nvd, "NVD_MAX_RETRIES", 2)
    monkeypatch.setattr(nvd, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(http_error))
    calls = {"count": 0}

    def _urlopen_side_effect(*_args, **_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise http_error
        return _Response()

    monkeypatch.setattr(nvd, "urlopen", _urlopen_side_effect)
    monkeypatch.setattr(nvd.time, "sleep", lambda *_args, **_kwargs: None)

    logger = MagicMock()
    result = nvd.query_nvd(keyword="apache", api_key=None, logger=logger)
    assert result == []
    assert logger.warning.called


def test_query_nvd_url_error_retry_then_success(monkeypatch):
    sample = {"vulnerabilities": []}

    class _Response:
        status = 200

        def read(self):
            return json.dumps(sample).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    from urllib.error import URLError

    url_error = URLError("nope")
    monkeypatch.setattr(nvd, "get_cached_result", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(nvd, "save_to_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(nvd, "NVD_MAX_RETRIES", 2)

    calls = {"count": 0}

    def _urlopen_side_effect(*_args, **_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise url_error
        return _Response()

    monkeypatch.setattr(nvd, "urlopen", _urlopen_side_effect)
    monkeypatch.setattr(nvd.time, "sleep", lambda *_args, **_kwargs: None)

    logger = MagicMock()
    result = nvd.query_nvd(keyword="apache", api_key=None, logger=logger)
    assert result == []
    assert logger.warning.called


def test_query_nvd_exception_retry_then_success(monkeypatch):
    sample = {"vulnerabilities": []}

    class _Response:
        status = 200

        def read(self):
            return json.dumps(sample).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(nvd, "get_cached_result", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(nvd, "save_to_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(nvd, "NVD_MAX_RETRIES", 2)

    calls = {"count": 0}

    def _urlopen_side_effect(*_args, **_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("boom")
        return _Response()

    monkeypatch.setattr(nvd, "urlopen", _urlopen_side_effect)
    monkeypatch.setattr(nvd.time, "sleep", lambda *_args, **_kwargs: None)

    logger = MagicMock()
    result = nvd.query_nvd(keyword="apache", api_key=None, logger=logger)
    assert result == []
    assert logger.debug.called


def test_clear_cache_removes_files(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "NVD_CACHE_DIR", str(tmp_path))
    cache_file = tmp_path / "test.json"
    cache_file.write_text("{}", encoding="utf-8")
    assert nvd.clear_cache() == 1
    assert not cache_file.exists()


def test_clear_cache_handles_errors(monkeypatch):
    monkeypatch.setattr(nvd, "NVD_CACHE_DIR", "/nope")
    monkeypatch.setattr(
        nvd.os, "listdir", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError())
    )
    assert nvd.clear_cache() == 0
