#!/usr/bin/env python3
"""
RedAudit - Power/Sleep Inhibition Tests
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import redaudit.core.power as power_module
from redaudit.core.power import SleepInhibitor


class TestSleepInhibitor(unittest.TestCase):
    @patch("redaudit.core.power.subprocess.Popen")
    @patch("redaudit.core.power.shutil.which", return_value="/usr/bin/caffeinate")
    @patch("redaudit.core.power.platform.system", return_value="Darwin")
    def test_macos_uses_caffeinate(self, mock_sys, mock_which, mock_popen):
        inst = SleepInhibitor()
        inst.start()
        mock_popen.assert_called()
        args = mock_popen.call_args[0][0]
        self.assertIn("caffeinate", args[0])
        self.assertIn("-dimsu", args)

    @patch("redaudit.core.power.subprocess.Popen")
    @patch("redaudit.core.power.shutil.which")
    @patch("redaudit.core.power.platform.system", return_value="Linux")
    def test_linux_uses_systemd_inhibit_when_available(self, mock_sys, mock_which, mock_popen):
        def which_side_effect(name):
            if name == "systemd-inhibit":
                return "/usr/bin/systemd-inhibit"
            return None

        mock_which.side_effect = which_side_effect
        inst = SleepInhibitor()
        inst.start()
        mock_popen.assert_called()
        args = mock_popen.call_args[0][0]
        self.assertIn("systemd-inhibit", args[0])

    @patch("redaudit.core.command_runner.subprocess.run")
    @patch("redaudit.core.power.subprocess.Popen")
    @patch("redaudit.core.power.shutil.which")
    @patch("redaudit.core.power.platform.system", return_value="Linux")
    def test_x11_xset_applied_when_display_set(self, mock_sys, mock_which, mock_popen, mock_run):
        def which_side_effect(name):
            if name == "xset":
                return "/usr/bin/xset"
            if name == "systemd-inhibit":
                return "/usr/bin/systemd-inhibit"
            return None

        mock_which.side_effect = which_side_effect
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        with patch.dict(os.environ, {"DISPLAY": ":0"}, clear=False):
            inst = SleepInhibitor()
            inst.start()
        # xset q + the 3 xset modifications
        self.assertGreaterEqual(mock_run.call_count, 1)

    @patch("redaudit.core.command_runner.subprocess.run")
    @patch("redaudit.core.power.subprocess.Popen")
    def test_dry_run_skips_all_external_commands(self, mock_popen, mock_run):
        inst = SleepInhibitor(dry_run=True)
        inst.start()
        inst.stop()
        mock_popen.assert_not_called()
        mock_run.assert_not_called()

    def test_start_returns_when_proc_exists(self):
        inst = SleepInhibitor()
        inst._proc = object()
        inst._start_caffeinate = MagicMock()
        inst._start_systemd_inhibit = MagicMock()
        inst._apply_x11_no_sleep = MagicMock()
        inst.start()
        inst._start_caffeinate.assert_not_called()
        inst._start_systemd_inhibit.assert_not_called()
        inst._apply_x11_no_sleep.assert_not_called()

    @patch("redaudit.core.power.platform.system", return_value="AIX")
    def test_start_unknown_platform_noop(self, _mock_sys):
        inst = SleepInhibitor()
        inst._start_caffeinate = MagicMock()
        inst._start_systemd_inhibit = MagicMock()
        inst._apply_x11_no_sleep = MagicMock()
        inst.start()
        inst._start_caffeinate.assert_not_called()
        inst._start_systemd_inhibit.assert_not_called()
        inst._apply_x11_no_sleep.assert_not_called()

    def test_log_levels(self):
        logger = MagicMock()
        inst = SleepInhibitor(logger=logger)
        inst._log("DEBUG", "debug")
        inst._log("WARNING", "warn")
        inst._log("INFO", "info")
        logger.debug.assert_called_once_with("debug")
        logger.warning.assert_called_once_with("warn")
        logger.info.assert_called_with("info")

    @patch("redaudit.core.power.shutil.which", return_value=None)
    def test_start_caffeinate_missing_binary(self, _mock_which):
        inst = SleepInhibitor()
        inst._start_caffeinate()
        self.assertIsNone(inst._proc)

    @patch("redaudit.core.power.subprocess.Popen", side_effect=RuntimeError("boom"))
    @patch("redaudit.core.power.shutil.which", return_value="/usr/bin/caffeinate")
    def test_start_caffeinate_handles_exception(self, _mock_which, _mock_popen):
        inst = SleepInhibitor()
        inst._start_caffeinate()
        self.assertIsNone(inst._proc)

    @patch("redaudit.core.power.shutil.which", return_value=None)
    def test_start_systemd_inhibit_missing_binary(self, _mock_which):
        inst = SleepInhibitor()
        inst._start_systemd_inhibit()
        self.assertIsNone(inst._proc)

    @patch("redaudit.core.power.subprocess.Popen", side_effect=RuntimeError("boom"))
    @patch("redaudit.core.power.shutil.which", return_value="/usr/bin/systemd-inhibit")
    def test_start_systemd_inhibit_handles_exception(self, _mock_which, _mock_popen):
        inst = SleepInhibitor()
        inst._start_systemd_inhibit()
        self.assertIsNone(inst._proc)

    def test_apply_x11_no_sleep_requires_display(self):
        inst = SleepInhibitor()
        with patch.dict(os.environ, {}, clear=True):
            with patch("redaudit.core.power._make_runner") as mock_runner:
                inst._apply_x11_no_sleep()
        mock_runner.assert_not_called()
        self.assertIsNone(inst._xset_state)

    def test_apply_x11_no_sleep_requires_xset(self):
        inst = SleepInhibitor()
        with patch.dict(os.environ, {"DISPLAY": ":0"}, clear=True):
            with patch("redaudit.core.power.shutil.which", return_value=None):
                inst._apply_x11_no_sleep()
        self.assertIsNone(inst._xset_state)

    def test_apply_x11_no_sleep_captures_state(self):
        inst = SleepInhibitor(logger=MagicMock())
        runner = MagicMock()
        runner.run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        state = power_module._XsetState(screensaver_enabled=True)
        with patch.dict(os.environ, {"DISPLAY": ":0"}, clear=True):
            with (
                patch("redaudit.core.power.shutil.which", return_value="/usr/bin/xset"),
                patch("redaudit.core.power._make_runner", return_value=runner),
                patch.object(inst, "_capture_xset_state", return_value=state),
            ):
                inst._apply_x11_no_sleep()
        self.assertIs(inst._xset_state, state)
        self.assertEqual(runner.run.call_count, 3)

    def test_apply_x11_no_sleep_handles_exception(self):
        inst = SleepInhibitor()
        with patch.dict(os.environ, {"DISPLAY": ":0"}, clear=True):
            with (
                patch("redaudit.core.power.shutil.which", return_value="/usr/bin/xset"),
                patch.object(inst, "_capture_xset_state", side_effect=RuntimeError("boom")),
            ):
                inst._apply_x11_no_sleep()
        self.assertIsNone(inst._xset_state)

    def test_restore_x11_state_skips_without_state(self):
        inst = SleepInhibitor()
        with patch.dict(os.environ, {"DISPLAY": ":0"}, clear=True):
            with patch("redaudit.core.power.shutil.which", return_value="/usr/bin/xset"):
                inst._restore_x11_state()
        self.assertIsNone(inst._xset_state)

    def test_restore_x11_state_clears_state(self):
        inst = SleepInhibitor()
        inst._xset_state = power_module._XsetState(screensaver_enabled=False)
        with patch.dict(os.environ, {"DISPLAY": ":0"}, clear=True):
            with (
                patch("redaudit.core.power.shutil.which", return_value="/usr/bin/xset"),
                patch.object(inst, "_restore_xset_state") as mock_restore,
            ):
                inst._restore_x11_state()
        mock_restore.assert_called_once()
        self.assertIsNone(inst._xset_state)

    def test_restore_x11_state_handles_exception(self):
        inst = SleepInhibitor()
        inst._xset_state = power_module._XsetState(screensaver_enabled=False)
        with patch.dict(os.environ, {"DISPLAY": ":0"}, clear=True):
            with (
                patch("redaudit.core.power.shutil.which", return_value="/usr/bin/xset"),
                patch.object(inst, "_restore_xset_state", side_effect=RuntimeError("boom")),
            ):
                inst._restore_x11_state()
        self.assertIsNone(inst._xset_state)

    def test_capture_xset_state_parsing(self):
        inst = SleepInhibitor()
        runner = MagicMock()
        runner.run.return_value = MagicMock(
            stdout=(
                "timeout: 600    cycle: 120\n"
                "Standby: 300    Suspend: 400    Off: 500\n"
                "DPMS is Enabled\n"
            ),
            stderr="",
            returncode=0,
        )
        with patch("redaudit.core.power._make_runner", return_value=runner):
            state = inst._capture_xset_state("/usr/bin/xset")
        self.assertEqual(state.screensaver_timeout, 600)
        self.assertEqual(state.screensaver_cycle, 120)
        self.assertEqual(state.dpms_standby, 300)
        self.assertEqual(state.dpms_suspend, 400)
        self.assertEqual(state.dpms_off, 500)
        self.assertTrue(state.dpms_enabled)
        self.assertTrue(state.screensaver_enabled)

    def test_restore_xset_state_runs_commands(self):
        inst = SleepInhibitor()
        runner = MagicMock()
        state = power_module._XsetState(
            screensaver_enabled=False,
            screensaver_timeout=120,
            screensaver_cycle=60,
            dpms_enabled=True,
            dpms_standby=300,
            dpms_suspend=400,
            dpms_off=500,
        )
        with patch("redaudit.core.power._make_runner", return_value=runner):
            inst._restore_xset_state("/usr/bin/xset", state)
        self.assertGreaterEqual(runner.run.call_count, 4)

    def test_stop_handles_terminate_and_kill_errors(self):
        inst = SleepInhibitor()
        proc = MagicMock()
        proc.terminate.side_effect = RuntimeError("boom")
        proc.wait.side_effect = RuntimeError("boom")
        proc.kill.side_effect = RuntimeError("boom")
        inst._proc = proc
        inst._restore_x11_state = MagicMock()
        inst.stop()
        self.assertIsNone(inst._proc)


if __name__ == "__main__":
    unittest.main()
