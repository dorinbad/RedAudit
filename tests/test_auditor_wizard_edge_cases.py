"""Tests for auditor.py wizard logic to push coverage to 95%+
Targets _configure_scan_interactive and all profile configurations.
"""

from unittest.mock import patch, MagicMock
import pytest
from redaudit.core.auditor import InteractiveNetworkAuditor


class MockWizardAuditor(InteractiveNetworkAuditor):
    def __init__(self):
        super().__init__()
        self.lang = "en"
        self.config = {"target_networks": [], "scan_vulnerabilities": True}
        self.rate_limit_delay = 0.0
        self.cryptography_available = True

    def t(self, key):
        return key

    def print_status(self, *args, **kwargs):
        pass

    def ask_choice(self, q, opts, default=0):
        return default

    def ask_choice_with_back(self, q, opts, default=0, **kwargs):
        return default

    def _ask_auditor_and_output_dir(self, defaults):
        pass

    def ask_yes_no(self, q, default="yes", **kwargs):
        return default == "yes"

    def ask_text(self, q, default="", **kwargs):
        return default

    def ask_num(self, q, min_val, max_val, default=0, **kwargs):
        return default

    def ask_number(self, q, default="all", **kwargs):
        return default

    def ask_network_range(self):
        return ["1.1.1.0/24"]

    def setup_encryption(self, **kwargs):
        pass


def test_wizard_express_profile():
    """Test Express profile configuration (profile 0)."""
    auditor = MockWizardAuditor()
    # ask_choice for profile = 0 (Express)
    with patch.object(auditor, "ask_choice", return_value=0):
        with patch("builtins.input", return_value=""):
            auditor._configure_scan_interactive({})
            assert auditor.config["scan_mode"] == "rapido"
            assert auditor.config["scan_vulnerabilities"] is False


def test_wizard_standard_profile_normal_timing():
    """Test Standard profile with Normal timing (profile 1, timing 1)."""
    auditor = MockWizardAuditor()
    # first call returns 1 (Standard), second returns 1 (Normal)
    with patch.object(auditor, "ask_choice", side_effect=[1, 1]):
        with patch.object(auditor, "ask_yes_no", return_value=True):
            with patch.object(auditor, "ask_num", return_value=10):
                with patch("builtins.input", return_value=""):
                    auditor._configure_scan_interactive({})
                    assert auditor.config["scan_mode"] == "normal"


def test_wizard_back_navigation():
    """Test 'Go back' navigation in timing screen (timing 3)."""
    auditor = MockWizardAuditor()
    # first: Standard (1), second: Back (3), third: Express (0)
    with patch.object(auditor, "ask_choice", side_effect=[1, 3, 0]):
        with patch("builtins.input", return_value=""):
            auditor._configure_scan_interactive({})
            assert auditor.config["scan_mode"] == "rapido"


def test_wizard_custom_profile():
    """Test Custom profile (profile 3) with full manual configuration."""
    auditor = MockWizardAuditor()
    # profile 3 = Custom. Map choice 2 to 'completo'
    with patch.object(
        auditor, "ask_choice", side_effect=[2, 2]
    ):  # Mock Exhaustive to reach that block
        with patch("builtins.input", return_value=""):
            auditor._configure_scan_interactive({})
            assert auditor.config["scan_mode"] == "completo"


def test_wizard_exhaustive_profile():
    """Test Exhaustive profile configuration (profile 2)."""
    auditor = MockWizardAuditor()
    # profile 2 = Exhaustive
    with patch.object(
        auditor, "ask_choice", side_effect=[2, 2]
    ):  # Exhaustive, then Aggressive timing
        with patch("builtins.input", return_value=""):
            auditor._configure_scan_interactive({})
            assert auditor.config["scan_mode"] == "completo"
            assert auditor.config["scan_vulnerabilities"] is True
