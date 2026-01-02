import unittest
import os
import sys
from unittest.mock import Mock, patch
from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.cli import main


class TestAggressiveCoverageBatch8(unittest.TestCase):
    def setUp(self):
        with (
            patch("redaudit.core.auditor.get_default_reports_base_dir", return_value="/tmp"),
            patch("redaudit.core.auditor.is_crypto_available", return_value=True),
        ):
            self.app = InteractiveNetworkAuditor()
            self.app.logger = Mock()

    @patch("termios.tcgetattr")
    @patch("termios.tcsetattr")
    @patch("tty.setraw")
    @patch("sys.stdin.fileno")
    def test_read_key_posix_up_down(self, mock_fileno, mock_setraw, mock_setattr, mock_getattr):
        mock_fileno.return_value = 0
        with patch("sys.stdin.read") as mock_read:
            mock_read.side_effect = ["\x1b", "[A"]
            self.assertEqual(self.app._read_key(), "up")
            mock_read.side_effect = ["\x1b", "[B"]
            self.assertEqual(self.app._read_key(), "down")
            mock_read.side_effect = ["\r"]
            self.assertEqual(self.app._read_key(), "enter")
            mock_read.side_effect = ["\x03"]
            with self.assertRaises(KeyboardInterrupt):
                self.app._read_key()

    def test_ask_yes_no_branches(self):
        with (
            patch.object(self.app, "_use_arrow_menu", return_value=True),
            patch.object(self.app, "_arrow_menu", return_value=0),
        ):
            self.assertTrue(self.app.ask_yes_no("q"))

        with (
            patch.object(self.app, "_use_arrow_menu", return_value=False),
            patch("redaudit.core.wizard.input", return_value="y"),
        ):
            self.assertTrue(self.app.ask_yes_no("q"))

    def test_ask_choice_with_back_navigation(self):
        with (
            patch.object(self.app, "_use_arrow_menu", return_value=False),
            patch("builtins.input", side_effect=["1", "back"]),
        ):
            # option 1 (index 0)
            self.assertEqual(self.app.ask_choice_with_back("q", ["o1"], step_num=2), 0)
            # "back" -> WIZARD_BACK (-1)
            self.assertEqual(self.app.ask_choice_with_back("q", ["o1"], step_num=2), -1)

    @patch("redaudit.cli.parse_arguments")
    @patch("sys.exit")
    def test_cli_diff_mode_success(self, mock_exit, mock_parse):
        args = Mock()
        args.diff = ["old.json", "new.json"]
        args.no_color = True
        mock_parse.return_value = args

        with (
            patch("redaudit.core.diff.generate_diff_report") as mock_gen,
            patch("builtins.open", unittest.mock.mock_open()),
            patch("os.chmod"),
        ):
            mock_gen.return_value = {
                "generated_at": "2023-01-01T00:00:00",
                "old_report": {"path": "o", "timestamp": "t", "total_hosts": 0},
                "new_report": {"path": "n", "timestamp": "t", "total_hosts": 0},
                "summary": {
                    "has_changes": False,
                    "new_hosts_count": 0,
                    "removed_hosts_count": 0,
                    "changed_hosts_count": 0,
                    "total_new_ports": 0,
                    "total_closed_ports": 0,
                    "total_new_vulnerabilities": 0,
                },
                "changes": {"new_hosts": [], "removed_hosts": [], "changed_hosts": []},
            }
            # Simulate exit to prevent fallthrough to scan logic
            mock_exit.side_effect = SystemExit(0)
            with self.assertRaises(SystemExit):
                main()
            mock_exit.assert_called_with(0)


class TestAuditorScanBatch8Extras(unittest.TestCase):
    def setUp(self):
        with (
            patch("redaudit.core.auditor.get_default_reports_base_dir", return_value="/tmp"),
            patch("redaudit.core.auditor.is_crypto_available", return_value=True),
        ):
            self.app = InteractiveNetworkAuditor()
            self.app.logger = Mock()

    def test_apply_net_discovery_identity_logic(self):
        host = {"ip": "1.2.3.4", "hostname": ""}
        self.app.results = {
            "net_discovery": {
                "netbios_hosts": [{"ip": "1.2.3.4", "name": "MOCK_HOST"}],
                "arp_hosts": [{"ip": "1.2.3.4", "mac": "AA:BB", "vendor": "V"}],
                "upnp_devices": [{"ip": "1.2.3.4", "device": "UPNP"}],
            }
        }
        self.app._apply_net_discovery_identity(host)
        self.assertEqual(host["hostname"], "MOCK_HOST")
        self.assertEqual(host["deep_scan"]["mac_address"], "AA:BB")


if __name__ == "__main__":
    unittest.main()
