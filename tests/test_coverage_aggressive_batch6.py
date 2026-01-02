"""Aggressive coverage push v6 - Targeting auditor.py and wizard.py missing branches"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import subprocess
from redaudit.core.auditor import InteractiveNetworkAuditor


class TestAggressiveCoverageBatch6(unittest.TestCase):

    def setUp(self):
        # We need to mock a lot of things to instantiate Auditor without side effects
        with (
            patch("redaudit.core.auditor.get_default_reports_base_dir", return_value="/tmp"),
            patch("redaudit.core.auditor.is_crypto_available", return_value=True),
        ):
            self.app = InteractiveNetworkAuditor()
            self.app.logger = Mock()

    def test_subprocess_management_coverage(self):
        """Cover auditor.py lines 875-900 (subprocess tracking)."""
        mock_proc = MagicMock(spec=subprocess.Popen)
        mock_proc.poll.return_value = None  # Running

        # Register
        self.app.register_subprocess(mock_proc)
        self.assertIn(mock_proc, self.app._active_subprocesses)

        # Unregister
        self.app.unregister_subprocess(mock_proc)
        self.assertNotIn(mock_proc, self.app._active_subprocesses)

        # Kill all
        self.app.register_subprocess(mock_proc)
        # Mock wait to trigger timeout then success
        mock_proc.wait.side_effect = [subprocess.TimeoutExpired(cmd="test", timeout=2), None]

        self.app.kill_all_subprocesses()
        self.assertTrue(mock_proc.terminate.called)
        self.assertTrue(mock_proc.kill.called)

    def test_kill_subprocess_error_path(self):
        """Cover auditor.py lines 898-900 (Exception in kill)."""
        mock_proc = MagicMock(spec=subprocess.Popen)
        mock_proc.poll.return_value = None
        mock_proc.terminate.side_effect = Exception("Mock kill error")

        self.app.register_subprocess(mock_proc)
        self.app.kill_all_subprocesses()
        self.assertTrue(self.app.logger.debug.called)

    @patch("builtins.input")
    def test_wizard_interruption_paths(self, mock_input):
        """Cover wizard.py KeyboardInterrupt in prompts."""
        # Don't mock sys.exit to avoid infinite loop in 'while True'
        with patch.object(self.app, "signal_handler") as mock_sig:
            mock_input.side_effect = KeyboardInterrupt()

            with self.assertRaises(SystemExit):
                self.app.ask_manual_network()

            self.assertTrue(mock_sig.called)

    def test_configure_scan_interactive_profile_branches(self):
        """Cover auditor.py lines 1056-1100 (Profile selection)."""
        # Mocking all dependencies of _configure_scan_interactive
        with (
            patch.object(self.app, "ask_choice", return_value=0),
            patch.object(self.app, "ask_yes_no", return_value=True),
            patch.object(self.app, "_ask_auditor_and_output_dir"),
        ):

            self.app._configure_scan_interactive({})
            self.assertEqual(self.app.config["scan_mode"], "rapido")

    def test_configure_scan_interactive_timing_branches(self):
        """Cover timing branches (1078-1089)."""
        with (
            patch.object(self.app, "ask_choice") as mock_choice,
            patch.object(self.app, "ask_yes_no", return_value=True),
            patch.object(self.app, "_ask_auditor_and_output_dir"),
        ):

            # Test Standard (1) then Stealth (0) timing.
            mock_choice.side_effect = [1, 0]
            self.app._configure_scan_interactive({})
            self.assertEqual(self.app.config.get("scan_mode"), "normal")
            self.assertEqual(self.app.config.get("nmap_timing"), "T1")


if __name__ == "__main__":
    unittest.main()
