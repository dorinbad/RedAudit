#!/usr/bin/env python3
"""
Extra coverage for wizard arrow menu navigation.
"""

import io

from redaudit.core.wizard import WizardMixin


class _DummyWizard(WizardMixin):
    def __init__(self):
        self.lang = "en"
        self.config = {}
        from unittest.mock import MagicMock

        self.ui = MagicMock()
        self.COLORS = {
            "FAIL": "",
            "BOLD": "",
            "HEADER": "",
            "ENDC": "",
            "CYAN": "",
            "OKBLUE": "",
            "WARNING": "",
            "OKGREEN": "",
        }

    def t(self, key, *args):
        if args:
            return f"{key}:{','.join(str(a) for a in args)}"
        return key

    def print_status(self, *_args, **_kwargs):
        return None


def test_arrow_menu_moves_down_and_selects(monkeypatch):
    wiz = _DummyWizard()
    keys = iter(["down", "enter"])

    monkeypatch.setattr(wiz, "_read_key", lambda: next(keys))
    monkeypatch.setattr(wiz, "_menu_width", lambda: 80)
    monkeypatch.setattr("sys.stdout", io.StringIO())

    choice = wiz._arrow_menu("q", ["one", "two"], default=0)
    assert choice == 1


def test_arrow_menu_digit_select(monkeypatch):
    wiz = _DummyWizard()
    keys = iter(["2"])

    monkeypatch.setattr(wiz, "_read_key", lambda: next(keys))
    monkeypatch.setattr(wiz, "_menu_width", lambda: 80)
    monkeypatch.setattr("sys.stdout", io.StringIO())

    choice = wiz._arrow_menu("q", ["one", "two"], default=0)
    assert choice == 1


def test_arrow_menu_esc_returns_current(monkeypatch):
    wiz = _DummyWizard()
    keys = iter(["esc"])

    monkeypatch.setattr(wiz, "_read_key", lambda: next(keys))
    monkeypatch.setattr(wiz, "_menu_width", lambda: 80)
    monkeypatch.setattr("sys.stdout", io.StringIO())

    choice = wiz._arrow_menu("q", ["one", "two"], default=1)
    assert choice == 1
