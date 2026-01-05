#!/usr/bin/env python3
"""
Extra coverage for updater perform_git_update paths.
"""

import os

from redaudit.core import updater


class _DummyRunner:
    def __init__(self, **_kwargs):
        self.check_output_called = False

    def check_output(self, *_args, **_kwargs):
        self.check_output_called = True
        raise RuntimeError("should not be called")


def test_perform_git_update_dry_run(monkeypatch):
    monkeypatch.setenv("REDAUDIT_DRY_RUN", "1")
    monkeypatch.setattr(updater, "CommandRunner", _DummyRunner)

    ok, msg = updater.perform_git_update(repo_path=os.getcwd(), lang="en")

    assert ok is True
    assert "Dry-run" in msg


def test_perform_git_update_tag_resolution_failure(monkeypatch):
    monkeypatch.delenv("REDAUDIT_DRY_RUN", raising=False)

    class _FailingRunner:
        def __init__(self, **_kwargs):
            return None

        def check_output(self, *_args, **_kwargs):
            raise RuntimeError("ls-remote failed")

    monkeypatch.setattr(updater, "CommandRunner", _FailingRunner)

    ok, msg = updater.perform_git_update(repo_path=os.getcwd(), lang="en", target_version="0.0.0")

    assert ok is False
    assert "Could not resolve tag" in msg
