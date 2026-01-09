#!/usr/bin/env python3
"""
Tests for Phase 4: Authenticated Scanning - Integration
"""

import unittest
from unittest.mock import MagicMock, patch
import sys
import os

from redaudit.cli import parse_arguments, configure_from_args
from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.core.credentials import CredentialProvider


class TestPhase4Integration(unittest.TestCase):

    def setUp(self):
        # Mock sys.argv to avoid messing with actual args
        self.original_argv = sys.argv
        sys.argv = ["redaudit"]

        # Mock UI for Auditor
        self.mock_ui = MagicMock()
        self.mock_ui.t.side_effect = lambda x, *args, **kwargs: x  # Dummy translation
        self.mock_ui.colors = {"CYAN": "", "ENDC": "", "OKBLUE": "", "HEADER": ""}

    def tearDown(self):
        sys.argv = self.original_argv

    def test_cli_auth_arguments(self):
        """Test parsing of new authentication arguments."""
        test_args = [
            "redaudit",
            "--target",
            "192.168.1.1",
            "--auth-provider",
            "env",
            "--ssh-user",
            "testuser",
            "--ssh-key",
            "/tmp/testkey",
            "--ssh-key-pass",
            "secretpass",
            "--ssh-trust-keys",
        ]
        with patch.object(sys, "argv", test_args):
            args = parse_arguments()
            self.assertEqual(args.auth_provider, "env")
            self.assertEqual(args.ssh_user, "testuser")
            self.assertEqual(args.ssh_key, "/tmp/testkey")
            self.assertEqual(args.ssh_key_pass, "secretpass")
            self.assertTrue(args.ssh_trust_keys)

            # Check config transfer
            config = {}

            # We need a dummy App object
            class DummyApp:
                def __init__(self):
                    self.config = {}

                def check_dependencies(self):
                    return True

                def show_legal_warning(self):
                    return True

            app = DummyApp()
            configure_from_args(app, args)

            self.assertEqual(app.config["auth_provider"], "env")
            self.assertEqual(app.config["auth_ssh_user"], "testuser")
            self.assertEqual(app.config["auth_ssh_key"], "/tmp/testkey")
            self.assertEqual(app.config["auth_ssh_key_pass"], "secretpass")
            self.assertTrue(app.config["auth_ssh_trust_keys"])

    @patch("redaudit.core.wizard.Wizard.ask_choice_with_back")
    @patch("redaudit.core.wizard.Wizard.ask_choice")
    @patch("builtins.input")
    def test_wizard_auth_step_custom_enabled(
        self, mock_input, mock_ask_choice, mock_ask_choice_back
    ):
        """Test that Authentication step in Custom profile configures Auth correctly."""

        auditor = InteractiveNetworkAuditor()
        auditor.ui = self.mock_ui
        auditor.ask_number = MagicMock(return_value=100)  # For limit, udp ports etc
        auditor.ask_yes_no = MagicMock(return_value=True)  # For confirm etc
        auditor.ask_net_discovery_options = MagicMock(return_value={})
        auditor.setup_encryption = MagicMock()
        auditor.ask_webhook_url = MagicMock(return_value=None)

        # Mocks for wizard flow

        # ask_choice (Wizard.ask_choice) mock:
        # 1. Profile selector -> 3 (Custom)
        # 2. UDP Profile (if UDP Full) -> 1 (Balanced)
        # 3. Step 8 Auth Method (Key) -> 0
        mock_ask_choice.side_effect = [3, 1, 0]

        # ask_choice_with_back mock:
        # 1. Step 1 Mode -> 2 (Full)
        # 2. Step 2 HyperScan -> 0 (Auto)
        # 3. Step 3 Vuln -> 1 (No)
        # 4. Step 4 CVE -> 1 (No)
        # 5. Step 6 UDP -> 1 (Full)
        # 6. Step 6b Topology -> 1 (Enabled)
        # 7. Step 7 NetDisc -> 1 (No)
        # 8. Step 8 Auth -> 0 (Yes - Enable)
        # 9. Step 9 Windows -> 1 (No)

        mock_ask_choice_back.side_effect = [
            2,  # Mode: Full
            0,  # HyperScan: Auto
            1,  # Vuln: No
            1,  # CVE: No
            1,  # UDP: Full
            1,  # Topo: Enabled
            1,  # NetDisc: No
            0,  # Auth: Yes (Enable)
            1,  # Windows: No
        ]

        # Inputs:
        # Updated Input flow for v4.2+ (Auth sub-menus)
        # 1. Auditor Name: "Tester"
        # 2. Output Dir: "/tmp"
        # 3. SSH Enable: "y"
        # 4. SSH User: "root"
        # 5. SSH Key: "/tmp/key"
        # 6. SMB Enable: "n"
        # 7. SNMP Enable: "n"
        mock_input.side_effect = ["Tester", "y", "root", "/tmp/key", "n", "n"]

        # Run with patched shutil and getpass
        with (
            patch("shutil.which", return_value=None),
            patch("getpass.getpass", return_value="secret"),
        ):
            auditor._configure_scan_interactive({})

        # Asserts
        self.assertEqual(auditor.config["scan_mode"], "completo")
        self.assertEqual(auditor.config["auth_ssh_user"], "root")
        key = auditor.config.get("auth_ssh_key")
        self.assertTrue(key.endswith("key"))
        self.assertIsNone(auditor.config.get("auth_ssh_pass"))

    def test_wizard_auth_disabled(self):
        """Test disabling Auth step."""
        from redaudit.core.wizard import Wizard

        w = Wizard()
        w.ui = self.mock_ui
        w.ask_yes_no = MagicMock(return_value=False)

        # Verify helper method exists and returns correct structure
        cfg = w.ask_auth_config()
        self.assertFalse(cfg["auth_enabled"])


if __name__ == "__main__":
    unittest.main()
