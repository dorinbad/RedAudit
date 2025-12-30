"""Tests for cli.py to push coverage to 95%+
Targets chmod exceptions, proxy failures, update checks, and scan results.
"""

import os
import sys
from unittest.mock import patch, MagicMock
import pytest
from redaudit.cli import main


def test_cli_max_hosts_arg():
    """Test --max-hosts (line 504)."""
    with patch("sys.argv", ["redaudit", "--target", "1.1.1.1", "--max-hosts", "5", "--yes"]):
        with patch("os.geteuid", return_value=0):
            with patch("redaudit.core.auditor.InteractiveNetworkAuditor") as MockAuditor:
                mock_app = MockAuditor.return_value
                mock_app.config = {}
                mock_app.check_dependencies.return_value = True
                mock_app.run_complete_scan.return_value = True
                with pytest.raises(SystemExit) as e:
                    main()
                assert e.value.code == 0
                assert mock_app.config["max_hosts_value"] == 5


def test_cli_diff_chmod_exception(tmp_path, monkeypatch):
    """Test chmod exception in diff mode (lines 657-658, 669-670)."""
    monkeypatch.chdir(tmp_path)
    # Create dummy files to compare
    (tmp_path / "old.json").write_text("{}", encoding="utf-8")
    (tmp_path / "new.json").write_text("{}", encoding="utf-8")

    mock_diff = {
        "generated_at": "2025-01-01",
        "old_report": {"path": "old.json", "timestamp": "2025-01-01T00:00:00", "total_hosts": 1},
        "new_report": {"path": "new.json", "timestamp": "2025-01-01T00:01:00", "total_hosts": 2},
        "changes": {"new_hosts": ["1.1.1.1"], "removed_hosts": [], "changed_hosts": []},
        "summary": {
            "new_hosts_count": 1,
            "removed_hosts_count": 0,
            "changed_hosts_count": 0,
            "total_new_ports": 0,
            "total_closed_ports": 0,
            "total_new_vulnerabilities": 0,
            "has_changes": True,
        },
    }

    with patch("sys.argv", ["redaudit", "--diff", "old.json", "new.json"]):
        with patch("redaudit.core.diff.generate_diff_report", return_value=mock_diff):
            with patch("os.chmod", side_effect=OSError("Permission denied")):
                with pytest.raises(SystemExit) as e:
                    main()
                assert e.value.code == 0


def test_cli_proxy_failure():
    """Test proxy connection failure (lines 720-726)."""
    with patch(
        "sys.argv", ["redaudit", "--target", "1.1.1.1", "--proxy", "socks5://bad:1080", "--yes"]
    ):
        with patch("os.geteuid", return_value=0):
            with patch("redaudit.core.proxy.ProxyManager") as MockProxy:
                mock_pm = MockProxy.return_value
                mock_pm.is_valid.return_value = True
                mock_pm.test_connection.return_value = (False, "Timeout")
                with patch("redaudit.core.auditor.InteractiveNetworkAuditor") as MockAuditor:
                    mock_app = MockAuditor.return_value
                    mock_app.check_dependencies.return_value = True
                    mock_app.t.return_value = "Proxy test failed"
                    with pytest.raises(SystemExit) as e:
                        main()
                    assert e.value.code == 1


def test_cli_update_check_interactive():
    """Test update check prompt in interactive mode (lines 742-751)."""
    with patch("sys.argv", ["redaudit"]):  # Interactive mode
        with patch("os.geteuid", return_value=0):
            with patch("redaudit.core.auditor.InteractiveNetworkAuditor") as MockAuditor:
                mock_app = MockAuditor.return_value
                mock_app.clear_screen = MagicMock()
                mock_app.print_banner = MagicMock()
                mock_app.ask_yes_no.return_value = True  # Yes to update check

                with patch(
                    "redaudit.core.updater.interactive_update_check", return_value=True
                ) as mock_update:
                    with pytest.raises(SystemExit) as e:
                        main()
                    assert e.value.code == 0
                    assert mock_update.called


def test_cli_main_menu_diff_failure():
    """Test diff failure in main menu (line 804)."""
    with patch("sys.argv", ["redaudit"]):
        with patch("os.geteuid", return_value=0):
            with patch("redaudit.core.auditor.InteractiveNetworkAuditor") as MockAuditor:
                mock_app = MockAuditor.return_value
                mock_app.ask_yes_no.return_value = False  # No early update check
                # choice 3 is diff, then choice 0 to exit
                mock_app.show_main_menu.side_effect = [3, 0]
                with patch("builtins.input", side_effect=["old.json", "new.json"]):
                    with patch("redaudit.core.diff.generate_diff_report", return_value=None):
                        with pytest.raises(SystemExit) as e:
                            main()
                        assert e.value.code == 0
                        assert mock_app.print_status.called


def test_cli_main_menu_update_check():
    """Test update check from main menu (line 772)."""
    with patch("sys.argv", ["redaudit"]):
        with patch("os.geteuid", return_value=0):
            with patch("redaudit.core.auditor.InteractiveNetworkAuditor") as MockAuditor:
                mock_app = MockAuditor.return_value
                mock_app.ask_yes_no.return_value = False  # No early update check
                # choice 2 is update check, then choice 0 to exit
                mock_app.show_main_menu.side_effect = [2, 0]
                with patch("redaudit.core.updater.interactive_update_check") as mock_update:
                    with pytest.raises(SystemExit) as e:
                        main()
                    assert e.value.code == 0
                    assert mock_update.called


def test_cli_stealth_mode_config():
    """Test stealth mode preserves configuration (lines 548-553)."""
    with patch("sys.argv", ["redaudit", "--target", "1.1.1.1", "--stealth", "--yes"]):
        with patch("os.geteuid", return_value=0):
            with patch("redaudit.core.auditor.InteractiveNetworkAuditor") as MockAuditor:
                mock_app = MockAuditor.return_value
                mock_app.config = {}
                mock_app.check_dependencies.return_value = True
                mock_app.run_complete_scan.return_value = True
                with pytest.raises(SystemExit) as e:
                    main()
                assert e.value.code == 0
                assert mock_app.config["stealth_mode"] is True
                assert mock_app.config["threads"] == 1
