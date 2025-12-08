#!/usr/bin/env python3
"""
RedAudit - Interactive Network Auditor
Copyright (C) 2026  Dorin Badea
GPLv3 License

DEPRECATED: This file is a backward-compatibility wrapper.
The main codebase has been refactored into the redaudit/ package.

For new usage, run:
  - python -m redaudit
  - or: from redaudit import InteractiveNetworkAuditor
"""

import sys
import os

# Add the directory containing this file to path for package import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Re-export everything from the package for backward compatibility
from redaudit import InteractiveNetworkAuditor, VERSION
from redaudit.utils.constants import (
    MAX_INPUT_LENGTH,
    MAX_CIDR_LENGTH,
    MAX_SUBPROCESS_RETRIES,
    DEFAULT_LANG,
)
from redaudit.utils.i18n import TRANSLATIONS
from redaudit.cli import main, parse_arguments, configure_from_args

__all__ = [
    'InteractiveNetworkAuditor',
    'VERSION',
    'MAX_INPUT_LENGTH',
    'MAX_CIDR_LENGTH',
    'MAX_SUBPROCESS_RETRIES',
    'DEFAULT_LANG',
    'TRANSLATIONS',
    'main',
    'parse_arguments',
    'configure_from_args',
]

if __name__ == "__main__":
    main()
