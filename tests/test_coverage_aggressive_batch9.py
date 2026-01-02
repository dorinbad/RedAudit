import unittest
import os
from unittest.mock import Mock, patch, mock_open
from redaudit.utils.paths import (
    _get_preferred_human_home_under_home,
    _resolve_home_dir_for_user,
    _read_xdg_documents_dir,
    resolve_invoking_user_owner,
    maybe_chown_to_invoking_user,
    maybe_chown_tree_to_invoking_user,
)
from redaudit.core.updater import (
    _extract_release_items,
    _inject_default_lang,
    _suggest_restart_command,
    _extract_release_date_from_notes,
)
from redaudit.core.siem import _severity_from_label
from redaudit.core.nvd import extract_product_version


class TestAggressiveCoverageBatch9(unittest.TestCase):

    # --- paths.py ---
    def test_paths_resolve_home_dir_none(self):
        """Line 45: return None at end of _resolve_home_dir_for_user."""
        with (
            patch("pwd.getpwnam", side_effect=Exception("Fail")),
            patch("os.path.expanduser", return_value="~unknown"),
        ):
            self.assertIsNone(_resolve_home_dir_for_user("unknown"))

    def test_paths_get_preferred_human_home_logic(self):
        """Line 111: return None at end of preferred home logic."""
        with patch("os.geteuid", return_value=0), patch("pwd.getpwall") as mock_pwd:

            # Multiple candidates, no "kali"
            mock_pwd.return_value = [
                Mock(pw_name="root", pw_uid=0, pw_dir="/root"),
                Mock(pw_name="u1", pw_uid=1001, pw_dir="/home/u1"),
                Mock(pw_name="u2", pw_uid=1002, pw_dir="/home/u2"),
            ]
            with patch("os.path.isdir", return_value=True):
                self.assertIsNone(_get_preferred_human_home_under_home())

            # Skip usernames (Lines 89, 95)
            mock_pwd.return_value = [
                Mock(pw_name=None, pw_uid=1001, pw_dir="/home/u1"),
                Mock(pw_name="u2", pw_uid=1002, pw_dir="/opt/u2"),
            ]
            self.assertIsNone(_get_preferred_human_home_under_home())

    def test_paths_read_xdg_documents_none(self):
        """Line 199: return None after loop in XDG reader."""
        m = mock_open(read_data="OTHER_VAR=val\n")
        with patch("builtins.open", m):
            self.assertIsNone(_read_xdg_documents_dir("/home/user"))

    def test_paths_resolve_invoking_owner_none(self):
        """Line 252: return None at end of owner resolver."""
        with (
            patch("os.environ.get", return_value=None),
            patch("redaudit.utils.paths.get_invoking_user", return_value="user"),
            patch("pwd.getpwnam", side_effect=Exception("Fail")),
        ):
            self.assertIsNone(resolve_invoking_user_owner())

    def test_paths_chown_exceptions_refined(self):
        """Exception handling in chown (Line 270, 302-303)."""
        with patch("redaudit.utils.paths.resolve_invoking_user_owner", return_value=(1000, 1000)):
            with patch("os.chown", side_effect=OSError("Access Denied")):
                maybe_chown_to_invoking_user("/tmp/test")

            with patch("os.walk") as mock_walk:
                mock_walk.return_value = [("/tmp", [], ["file1"])]
                with patch("os.chown", side_effect=Exception("Fail")):
                    maybe_chown_tree_to_invoking_user("/tmp")

    # --- updater.py ---
    def test_updater_normalize_heading_complex(self):
        """Line 280, 290: Accent normalization in changelog."""
        notes = "### Añadido\n- feature\n### Corregido\n- bug"
        res = _extract_release_items(notes)
        self.assertIn("feature", res["highlights"])
        self.assertIn("bug", res["highlights"])

    def test_updater_extract_date_none(self):
        """Line 252: date extraction failure."""
        self.assertIsNone(_extract_release_date_from_notes("no date", "1.0.0"))

    def test_updater_inject_lang_fail(self):
        """Line 718: injection failure handling."""
        with patch("builtins.open", side_effect=Exception("Open Fail")):
            self.assertFalse(_inject_default_lang("/tmp/no", "es"))

    def test_updater_suggest_restart(self):
        """Line 571: sudo restart hint."""
        with patch("os.geteuid", return_value=0):
            self.assertIn("sudo", _suggest_restart_command())
        with patch("os.geteuid", return_value=1000):
            self.assertNotIn("sudo", _suggest_restart_command())

    # --- siem.py ---
    def test_siem_severity_fallback(self):
        """Line 43: severity mapping fallback."""
        lbl, score = _severity_from_label("non-existent")
        self.assertEqual(lbl, "info")
        self.assertEqual(score, 10)

    # --- nvd.py ---
    def test_nvd_extract_product_version_fail(self):
        """Line 177: regex failure."""
        p, v = extract_product_version("OnlyProductNoVersion")
        self.assertIsNone(p)

    # --- auditor_scan.py (Identity Score) ---
    def test_auditor_score_extra_signals(self):
        """Identity score signals (Lines 656-701)."""
        from redaudit.core.auditor import InteractiveNetworkAuditor

        with (
            patch("redaudit.core.auditor.get_default_reports_base_dir", return_value="/tmp"),
            patch("redaudit.core.auditor.is_crypto_available", return_value=True),
        ):
            app = InteractiveNetworkAuditor()

            host = {
                "ip": "1.2.3.4",
                "ports": [],
                "agentless_fingerprint": {"http_title": "Title"},
                "phase0_enrichment": {"dns_reverse": "test.local"},
            }
            app.results["net_discovery"] = {
                "upnp_devices": [{"ip": "1.2.3.4", "device_type": "gateway"}]
            }
            score, signals = app._compute_identity_score(host)
            self.assertIn("upnp_router", signals)
            self.assertIn("http_probe", signals)
            self.assertIn("dns_reverse", signals)

    # --- constants.py ---
    def test_constants_coverage_threads(self):
        """Line 53: cpu_count logic."""
        from redaudit.utils.constants import suggest_threads

        with patch("os.cpu_count", return_value=None):
            self.assertEqual(suggest_threads(), 4)
        with patch("os.cpu_count", return_value=32):
            self.assertEqual(suggest_threads(), 12)  # Caps at 12 hardcoded

    def test_constants_version_resolution(self):
        """Coverage for _read_packaged_version_file and _resolve_version logic."""
        from redaudit.utils.constants import (
            _read_packaged_version_file,
            _read_pyproject_version,
            _resolve_version,
        )

        # 1. _read_packaged_version_file
        # Mock Path to return a valid VERSION file
        with patch("redaudit.utils.constants.Path") as mock_path:
            # Case A: Valid
            mock_file = Mock()
            mock_file.is_file.return_value = True
            mock_file.read_text.return_value = "1.2.3"
            mock_path.return_value.resolve.return_value.parents.__getitem__.return_value.__truediv__.return_value = (
                mock_file
            )
            self.assertEqual(_read_packaged_version_file(), "1.2.3")

            # Case B: Invalid regex
            mock_file.read_text.return_value = "invalid-ver"
            self.assertIsNone(_read_packaged_version_file())

            # Case C: Exception
            mock_file.read_text.side_effect = Exception("Read error")
            self.assertIsNone(_read_packaged_version_file())

        # 2. _read_pyproject_version
        with patch("redaudit.utils.constants.Path") as mock_path:
            # Case: Valid pyproject
            mock_file = Mock()
            mock_file.is_file.return_value = True
            mock_file.read_text.return_value = 'version = "3.9.0"\n'
            mock_path.return_value.resolve.return_value.parents.__getitem__.return_value.__truediv__.return_value = (
                mock_file
            )
            self.assertEqual(_read_pyproject_version(), "3.9.0")

            # Case: No match
            mock_file.read_text.return_value = "no version here"
            self.assertIsNone(_read_pyproject_version())

            # Case: Exception
            mock_file.read_text.side_effect = Exception("Fail")
            self.assertIsNone(_read_pyproject_version())

        # 3. _resolve_version priority
        # Case: importlib.metadata works
        with patch("importlib.metadata.version", return_value="1.0.0"):
            self.assertEqual(_resolve_version(), "1.0.0")

        # Case: importlib fails, packaged file works
        with (
            patch("importlib.metadata.version", side_effect=Exception),
            patch("redaudit.utils.constants._read_packaged_version_file", return_value="2.0.0"),
        ):
            self.assertEqual(_resolve_version(), "2.0.0")

        # Case: Fallback to pyproject
        with (
            patch("importlib.metadata.version", side_effect=Exception),
            patch("redaudit.utils.constants._read_packaged_version_file", return_value=None),
            patch("redaudit.utils.constants._read_pyproject_version", return_value="3.0.0"),
        ):
            self.assertEqual(_resolve_version(), "3.0.0")

        # Case: Final fallback
        with (
            patch("importlib.metadata.version", side_effect=Exception),
            patch("redaudit.utils.constants._read_packaged_version_file", return_value=None),
            patch("redaudit.utils.constants._read_pyproject_version", return_value=None),
        ):
            self.assertEqual(_resolve_version(), "0.0.0-dev")


if __name__ == "__main__":
    unittest.main()
