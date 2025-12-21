#!/usr/bin/env python3
"""
RedAudit - Tests for OUI lookup helpers.
"""

import sys
import time
import types

from redaudit.utils import oui_lookup


def test_normalize_oui_formats():
    assert oui_lookup.normalize_oui("aa:bb:cc:dd:ee:ff") == "AABBCC"
    assert oui_lookup.normalize_oui("AA-BB-CC-11-22-33") == "AABBCC"
    assert oui_lookup.normalize_oui("aabb.ccdd.eeff") == "AABBCC"


def test_get_vendor_with_fallback_prefers_local(monkeypatch):
    def _fail(*_args, **_kwargs):
        raise AssertionError("online lookup should not be called")

    monkeypatch.setattr(oui_lookup, "lookup_vendor_online", _fail)
    assert oui_lookup.get_vendor_with_fallback("aa:bb:cc:dd:ee:ff", local_vendor="Acme") == "Acme"


def test_lookup_vendor_online_caches_success(monkeypatch):
    class _Response:
        status_code = 200
        text = "Acme Corp"

    oui_lookup.clear_cache()
    oui_lookup._LAST_REQUEST_TIME = 0.0

    times = iter([1000.0, 1000.0])
    monkeypatch.setattr(time, "time", lambda: next(times))
    monkeypatch.setattr(time, "sleep", lambda *_args, **_kwargs: None)

    dummy_requests = types.SimpleNamespace(get=lambda *_args, **_kwargs: _Response())
    monkeypatch.setitem(sys.modules, "requests", dummy_requests)

    vendor = oui_lookup.lookup_vendor_online("aa:bb:cc:dd:ee:ff")
    assert vendor == "Acme Corp"
    assert oui_lookup._VENDOR_CACHE["AABBCC"] == "Acme Corp"


def test_lookup_vendor_online_caches_miss(monkeypatch):
    class _Response:
        status_code = 404
        text = "Not found"

    oui_lookup.clear_cache()
    oui_lookup._LAST_REQUEST_TIME = 0.0

    monkeypatch.setattr(time, "time", lambda: 1000.0)
    monkeypatch.setattr(time, "sleep", lambda *_args, **_kwargs: None)

    dummy_requests = types.SimpleNamespace(get=lambda *_args, **_kwargs: _Response())
    monkeypatch.setitem(sys.modules, "requests", dummy_requests)

    vendor = oui_lookup.lookup_vendor_online("aa:bb:cc:dd:ee:ff")
    assert vendor is None
    assert "AABBCC" in oui_lookup._VENDOR_CACHE
    assert oui_lookup._VENDOR_CACHE["AABBCC"] is None
