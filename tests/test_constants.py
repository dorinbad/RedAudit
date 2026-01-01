#!/usr/bin/env python3
"""
Tests for thread suggestion helper.
"""

import os

from redaudit.utils.constants import MAX_THREADS, MIN_THREADS, suggest_threads


def test_suggest_threads_minimum(monkeypatch):
    monkeypatch.setattr(os, "cpu_count", lambda: 1)
    assert suggest_threads() == MIN_THREADS + 1


def test_suggest_threads_caps(monkeypatch):
    monkeypatch.setattr(os, "cpu_count", lambda: 64)
    assert suggest_threads() == min(12, MAX_THREADS)


def test_suggest_threads_fallback_none(monkeypatch):
    monkeypatch.setattr(os, "cpu_count", lambda: None)
    expected = max(MIN_THREADS + 1, min(4, 12, MAX_THREADS))
    assert suggest_threads() == expected


def test_suggest_threads_fallback_exception(monkeypatch):
    def _boom():
        raise RuntimeError("fail")

    monkeypatch.setattr(os, "cpu_count", _boom)
    expected = max(MIN_THREADS + 1, min(4, 12, MAX_THREADS))
    assert suggest_threads() == expected
