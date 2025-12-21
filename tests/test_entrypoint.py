#!/usr/bin/env python3
"""
RedAudit - Tests for module entrypoints.
"""

import runpy
from unittest.mock import patch


def test_module_entrypoint_invokes_cli_main():
    with patch("redaudit.cli.main") as mocked:
        runpy.run_module("redaudit.__main__", run_name="__main__")
        mocked.assert_called_once()
