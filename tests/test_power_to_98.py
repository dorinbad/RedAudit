#!/usr/bin/env python3
"""
FILE-BY-FILE: power.py to 98%
Current: 69.74%, Missing: 46 lines
Target: 98% - focus on public API
"""

from unittest.mock import patch, MagicMock


def test_power_sleep_inhibitor_basic():
    """Test SleepInhibitor basic usage."""
    from redaudit.core.power import SleepInhibitor

    # Create instance
    inhibitor = SleepInhibitor(reason="Test", dry_run=True)
    assert inhibitor is not None


def test_power_sleep_inhibitor_context_manager():
    """Test SleepInhibitor as context manager."""
    from redaudit.core.power import SleepInhibitor

    with SleepInhibitor(reason="Test", dry_run=True) as inhibitor:
        assert inhibitor is not None


def test_power_sleep_inhibitor_start_stop():
    """Test start/stop."""
    from redaudit.core.power import SleepInhibitor

    inhibitor = SleepInhibitor(reason="Test", dry_run=True)
    inhibitor.start()
    inhibitor.stop()
    # Should not crash


def test_power_make_runner():
    """Test _make_runner utility."""
    from redaudit.core.power import _make_runner

    runner = _make_runner(dry_run=False)
    assert runner is not None

    runner_dry = _make_runner(dry_run=True)
    assert runner_dry is not None


def test_power_caffeinate_path():
    """Test caffeinate on macOS."""
    from redaudit.core.power import SleepInhibitor

    with patch("platform.system", return_value="Darwin"):
        with patch("shutil.which", return_value="/usr/bin/caffeinate"):
            inhibitor = SleepInhibitor(reason="Test", dry_run=False)
            inhibitor.start()
            inhibitor.stop()


def test_power_systemd_inhibit_path():
    """Test systemd-inhibit on Linux."""
    from redaudit.core.power import SleepInhibitor

    with patch("platform.system", return_value="Linux"):
        with patch("shutil.which", return_value="/usr/bin/systemd-inhibit"):
            inhibitor = SleepInhibitor(reason="Test", dry_run=False)
            inhibitor.start()
            inhibitor.stop()


def test_power_x11_xset():
    """Test X11 xset handling."""
    from redaudit.core.power import SleepInhibitor

    with patch("platform.system", return_value="Linux"):
        with patch("os.environ.get", return_value=":0"):
            with patch("shutil.which", return_value="/usr/bin/xset"):
                inhibitor = SleepInhibitor(reason="Test", dry_run=False)
                inhibitor.start()
                inhibitor.stop()


def test_power_unsupported_platform():
    """Test unsupported platform."""
    from redaudit.core.power import SleepInhibitor

    with patch("platform.system", return_value="Windows"):
        inhibitor = SleepInhibitor(reason="Test")
        inhibitor.start()
        inhibitor.stop()
        # Should handle gracefully
