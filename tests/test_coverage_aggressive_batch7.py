"""Aggressive coverage push v7 - Progress bars and Back navigation"""

import unittest
from unittest.mock import Mock, patch
from redaudit.core.auditor import InteractiveNetworkAuditor


class TestAggressiveCoverageBatch7(unittest.TestCase):

    def setUp(self):
        with (
            patch("redaudit.core.auditor.get_default_reports_base_dir", return_value="/tmp"),
            patch("redaudit.core.auditor.is_crypto_available", return_value=True),
        ):
            self.app = InteractiveNetworkAuditor()
            self.app.logger = Mock()

    def test_progress_callbacks_direct(self):
        """Cover progress callbacks (v3.9.0 extractions)."""
        mock_prog = Mock()
        mock_task = Mock()

        # Test _nd_progress_callback
        self.app._nd_progress_callback("Test", 50, 100, mock_prog, mock_task, 0.0)
        self.assertTrue(mock_prog.update.called)

        # Test heartbeat trigger (force now - start > 30s)
        with patch("time.time", return_value=40.0):
            # Reset heartbeat tracking if any
            if hasattr(self.app, "_nd_last_heartbeat"):
                del self.app._nd_last_heartbeat
            self.app._nd_progress_callback("HB", 60, 100, mock_prog, mock_task, 0.0)

        # Test _nuclei_progress_callback
        self.app._nuclei_progress_callback(5, 10, "00:30", mock_prog, mock_task, 0.0, 300)
        self.assertTrue(mock_prog.update.called)

    def test_udp_profile_selection_branches(self):
        """Cover UDP port profiles in Wizard (lines 1474-1498)."""
        with (
            patch.object(self.app, "ask_choice") as mock_choice,
            patch.object(self.app, "ask_choice_with_back") as mock_back,
            patch.object(self.app, "ask_yes_no") as mock_yesno,
            patch.object(self.app, "ask_number") as mock_num,
            patch.object(self.app, "ask_webhook_url", return_value=""),
            patch.object(self.app, "setup_nvd_api_key"),
            patch.object(self.app, "setup_encryption"),
            patch.object(self.app, "_ask_auditor_and_output_dir"),
        ):

            # Sequence:
            # 1. Profile selector -> 3 (Custom)
            # 2. Step 6: sub_profile -> 4 (Custom)
            # 3. Step 7: redteam_choice -> 0
            mock_choice.side_effect = [3, 4, 0, 0, 0, 0, 0, 0, 0, 0]

            mock_back.side_effect = [
                1,
                0,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]

            # mock_num sequence: S1 (limit), S2 (threads), S2 (rate delay), S6 (udp)
            mock_num.side_effect = ["all", 10, 1, 123, 123, 123, 123, 123]

            mock_yesno.return_value = True

            with (
                patch("builtins.input", return_value="https://test.com"),
                patch.object(self.app, "ask_net_discovery_options", return_value={}),
            ):
                self.app.config["scan_mode"] = "normal"
                self.app.config["deep_id_scan"] = True
                self.app.config["scan_vulnerabilities"] = True
                self.app._configure_scan_interactive({})

            self.assertEqual(self.app.config.get("udp_top_ports"), 123)

    def test_wizard_back_navigation_flow(self):
        """Cover WIZARD_BACK in various steps."""
        with (
            patch.object(self.app, "ask_choice") as mock_choice,
            patch.object(self.app, "ask_choice_with_back") as mock_back,
            patch.object(self.app, "ask_yes_no", return_value=True),
            patch.object(self.app, "ask_number", return_value=123),
            patch.object(self.app, "ask_webhook_url", return_value=""),
            patch.object(self.app, "setup_encryption"),
            patch.object(self.app, "setup_nvd_api_key"),
            patch.object(self.app, "_ask_auditor_and_output_dir"),
        ):

            # Profile 3, then subsequent returns 0
            mock_choice.side_effect = [3] + [0] * 20

            # Sequence: S1, S3, S4(BACK), S3, S4, ...
            mock_back.side_effect = [
                0,  # step 1
                0,  # step 3
                self.app.WIZARD_BACK,  # step 4 back to 3
                0,  # step 3 again
                0,  # step 4 again
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,  # finish
            ]

            with (
                patch("builtins.input", return_value="test"),
                patch.object(self.app, "ask_net_discovery_options", return_value={}),
            ):
                self.app.config["scan_mode"] = "normal"
                self.app._configure_scan_interactive({})

            self.assertTrue(mock_back.called)

    def test_wizard_express_profile(self):
        """Cover Express Profile (choice 0)."""
        with (
            patch.object(self.app, "ask_choice", return_value=0),
            patch.object(self.app, "ask_yes_no", return_value=True),
            patch.object(self.app, "ask_number", return_value=123),
            patch.object(self.app, "_ask_auditor_and_output_dir"),
        ):

            self.app._configure_scan_interactive({})
            self.assertEqual(self.app.rate_limit_delay, 0.0)

    def test_wizard_exhaustive_profile(self):
        """Cover Exhaustive Profile (choice 2)."""
        with (
            patch.object(self.app, "ask_choice", return_value=2),
            patch.object(self.app, "ask_yes_no", return_value=True),
            patch.object(self.app, "ask_number", return_value=123),
            patch.object(self.app, "setup_nvd_api_key"),
            patch.object(self.app, "setup_encryption"),
            patch.object(self.app, "_ask_auditor_and_output_dir"),
        ):

            self.app._configure_scan_interactive({})
            self.assertEqual(self.app.config.get("udp_top_ports"), 500)

    def test_wizard_standard_profile(self):
        """Cover Standard Profile (choice 1)."""
        with (
            patch.object(self.app, "ask_choice", return_value=1),
            patch.object(self.app, "ask_yes_no", return_value=True),
            patch.object(self.app, "ask_number", return_value=123),
            patch.object(self.app, "_ask_auditor_and_output_dir"),
        ):

            self.app._configure_scan_interactive({})
            self.assertEqual(self.app.config.get("scan_mode"), "normal")


if __name__ == "__main__":
    unittest.main()
