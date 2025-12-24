import io
import sys
import pytest
import shutil
import os
from unittest.mock import MagicMock, patch, mock_open
from redaudit.core.wizard import WizardMixin

WIZARD_BACK = WizardMixin.WIZARD_BACK


class MockWizard(WizardMixin):
    def __init__(self):
        self.lang = "en"
        self.config = {}
        self.COLORS = {
            "FAIL": "\033[91m",
            "BOLD": "\033[1m",
            "HEADER": "\033[95m",
            "ENDC": "\033[0m",
            "CYAN": "\033[96m",
            "OKBLUE": "\033[94m",
            "WARNING": "\033[93m",
            "OKGREEN": "\033[92m",
        }

    def t(self, key, *args):
        if args:
            return f"{key}:{','.join(str(a) for a in args)}"
        return key

    def print_status(self, msg, level="INFO"):
        pass

    def signal_handler(self, sig, frame):
        pass


@pytest.fixture
def wiz():
    return MockWizard()


# -------------------------------------------------------------------------
# Arrow Menu Logic
# -------------------------------------------------------------------------


def test_arrow_menu_navigation_detailed(wiz):
    # Coverage for: left, right, h, j, k, l, digit out of range, esc
    keys = [
        "left",
        "right",
        "h",
        "j",
        "k",
        "l",
        "9",  # out of range
        "1",  # valid digit
        "enter",  # select
    ]
    with (
        patch.object(wiz, "_read_key", side_effect=keys),
        patch.object(wiz, "_menu_width", return_value=80),
        patch("sys.stdout", new=io.StringIO()),
    ):
        res = wiz._arrow_menu("Q", ["A", "B"])
        assert res == 0


def test_arrow_menu_rendering_branches(wiz):
    with (
        patch.object(wiz, "_read_key", side_effect=["enter"]),
        patch.object(wiz, "_menu_width", return_value=20),
        patch("sys.stdout", new=io.StringIO()),
    ):
        wiz._arrow_menu("Long Question", ["Short"], header="H")


def test_truncate_ansi_complex(wiz):
    text = "\x1b[1mBOLD\x1b[0m\x1b[31mRED"
    res = wiz._truncate_menu_text(text, 6)
    assert "..." in res
    assert wiz._truncate_menu_text("abcde", 2) == "ab"


# -------------------------------------------------------------------------
# Choice and Nav Logic
# -------------------------------------------------------------------------


def test_ask_choice_with_back_text_fallback(wiz):
    with patch.object(wiz, "_use_arrow_menu", return_value=False):
        with patch("builtins.input", side_effect=["", "invalid", "0"]):
            assert wiz.ask_choice_with_back("Q", ["A"], default=0, step_num=2) == 0
            assert wiz.ask_choice_with_back("Q", ["A"], step_num=2) == WIZARD_BACK


def test_ask_choice_fallback_kb_interrupt(wiz):
    with patch.object(wiz, "_use_arrow_menu", return_value=False):
        with patch("builtins.input", side_effect=KeyboardInterrupt), pytest.raises(SystemExit):
            wiz.ask_choice("Q", ["A"])


def test_ask_yes_no_kb_interrupt(wiz):
    with patch.dict(os.environ, {"REDAUDIT_BASIC_PROMPTS": "1"}):
        with patch("builtins.input", side_effect=KeyboardInterrupt), pytest.raises(SystemExit):
            wiz.ask_yes_no("Q")


# -------------------------------------------------------------------------
# Defaults and Config
# -------------------------------------------------------------------------


def test_show_defaults_summary_all_fields(wiz):
    data = {
        "target_networks": ["1.1.1.1"],
        "scan_mode": "normal",
        "threads": 4,
        "output_dir": "/tmp",
        "rate_limit": 0.5,
        "udp_mode": "full",
        "udp_top_ports": 500,
        "topology_enabled": True,
        "scan_vulnerabilities": True,
        "cve_lookup_enabled": False,
        "generate_txt": True,
        "generate_html": False,
    }
    with patch("sys.stdout", new=io.StringIO()):
        wiz._show_defaults_summary(data)
        wiz._show_defaults_summary({"topology_enabled": None})


def test_apply_run_defaults_variants(wiz):
    wiz._apply_run_defaults({"rate_limit": 70, "threads": -1})
    assert wiz.rate_limit_delay == 60.0
    wiz._apply_run_defaults({"rate_limit": -5})
    assert wiz.rate_limit_delay == 0.0


# -------------------------------------------------------------------------
# Input prompts
# -------------------------------------------------------------------------


def test_ask_number_full_coverage(wiz):
    # Consolidate and provide enough inputs
    inputs = [
        "",  # default for todos -> all
        "",  # default for all -> all
        "50",  # out of range for min=1, max=10
        "100",  # out of range
        "5",  # valid
    ]
    with patch("builtins.input", side_effect=inputs):
        wiz.lang = "es"
        assert wiz.ask_number("Q", default="todos") == "all"
        wiz.lang = "en"
        assert wiz.ask_number("Q", default="all") == "all"
        assert wiz.ask_number("Q", min_val=1, max_val=10) == 5


def test_ask_manual_network_errors(wiz):
    with (
        patch("builtins.input", side_effect=["invalid", KeyboardInterrupt]),
        pytest.raises(SystemExit),
    ):
        wiz.ask_manual_network()


# -------------------------------------------------------------------------
# Webhook and Advanced
# -------------------------------------------------------------------------


def test_ask_webhook_kb_interrupt_and_invalid(wiz):
    with patch.object(wiz, "ask_yes_no", return_value=True):
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            assert wiz.ask_webhook_url() == ""
        with patch("builtins.input", side_effect=["ftp://bad", ""]):
            assert wiz.ask_webhook_url() == ""


def test_ask_net_discovery_kb_interrupt(wiz):
    with patch.object(wiz, "ask_yes_no", return_value=True):
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            res = wiz.ask_net_discovery_options()
            assert res["snmp_community"] == "public"


# -------------------------------------------------------------------------
# OS / Hardware
# -------------------------------------------------------------------------


def test_clear_screen_variants(wiz):
    wiz.config["dry_run"] = False
    with patch("os.system"):
        wiz.clear_screen()
    wiz.config["dry_run"] = True
    wiz.clear_screen()


def test_read_key_nt_branch(wiz, monkeypatch):
    monkeypatch.setattr(os, "name", "nt")
    mock_msvcrt = MagicMock()
    mock_msvcrt.getch.side_effect = [b"a", b"\r", b"\x03"]
    with patch.dict("sys.modules", {"msvcrt": mock_msvcrt}):
        assert wiz._read_key() == "a"
        assert wiz._read_key() == "enter"
        with pytest.raises(KeyboardInterrupt):
            wiz._read_key()


def test_read_key_linux_branches(wiz):
    with (
        patch("termios.tcgetattr", return_value=[]),
        patch("termios.tcsetattr"),
        patch("tty.setraw"),
        patch("sys.stdin.fileno", return_value=0),
        patch("sys.stdin.read", side_effect=["\x1b", "xy"]),
    ):
        assert wiz._read_key() == "esc"


def test_menu_width_edges(wiz):
    with patch("shutil.get_terminal_size", return_value=MagicMock(columns=2)):
        assert wiz._menu_width() == 2
    with patch("shutil.get_terminal_size", return_value=MagicMock(columns=1)):
        assert wiz._menu_width() == 1


def test_show_main_menu_kb_interrupt(wiz):
    with patch.object(wiz, "_use_arrow_menu", return_value=False):
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            assert wiz.show_main_menu() == 0
