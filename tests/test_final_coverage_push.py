"""Final coverage push targeting missing lines in traffic.py, i18n.py, and updater.py."""

import os
import sys
import shutil
import subprocess
import pytest
import textwrap
from unittest.mock import patch, MagicMock, ANY
from redaudit.core.scanner.traffic import capture_traffic_snippet, start_background_capture
from redaudit.utils.i18n import detect_preferred_language
from redaudit.core.updater import (
    check_for_updates,
    render_update_summary_for_cli,
    perform_git_update,
    format_release_notes_for_cli,
    restart_self,
    compute_tree_diff,
    _inject_default_lang,
    _show_restart_terminal_notice,
    _pause_for_restart_terminal,
)


# --- traffic.py ---
def test_traffic_finalize_coverage():
    """Test start_background_capture with sanitization failure (line 175-176)."""
    with patch("redaudit.core.scanner.traffic.sanitize_ip", return_value=None):
        res = start_background_capture("invalid", "/tmp", [], {})
        assert res is None


def test_traffic_snippet_finalize():
    """Test capture_traffic_snippet with sanitization failure (line 68-69)."""
    with patch("redaudit.core.scanner.traffic.sanitize_ip", return_value=None):
        res = capture_traffic_snippet("invalid", "/tmp", [], {})
        assert res is None


def test_traffic_timeouts_and_errors():
    """Test timeouts and errors in capture_traffic_snippet (lines 115, 131, 134-135)."""
    # 1. Timeout during tcpdump
    with patch("redaudit.core.scanner.traffic.sanitize_ip", return_value="1.2.3.4"):
        with patch("subprocess.Popen") as mock_popen:
            # tcpdump process (first call)
            p1 = MagicMock()
            p1.wait.side_effect = subprocess.TimeoutExpired(cmd="tcpdump", timeout=5)
            p1.stdout = MagicMock()  # context manager
            p1.poll.return_value = None

            mock_popen.return_value = p1

            res = capture_traffic_snippet("1.2.3.4", "/tmp", [], {})
            assert res is None  # Timeout -> kill -> return None/Empty?
            # actually capture_traffic_snippet returns analyzed data or None?
            # It returns List[Dict]. If timeout/fail, likely empty list or handle exception.

    # 2. tshark timeout or execution error
    # We need to pass the first step (tcpdump success) to reach tshark
    with patch("redaudit.core.scanner.traffic.sanitize_ip", return_value="1.2.3.4"):
        with patch("subprocess.Popen") as mock_popen:
            # tcpdump success
            p1 = MagicMock()
            p1.wait.return_value = 0

            # tshark fail (second call)
            p2 = MagicMock()
            # Simulate generic exception
            p2.communicate.side_effect = Exception("General failure")

            mock_popen.side_effect = [p1, p2]

            res = capture_traffic_snippet("1.2.3.4", "/tmp", [], {})
            # Should catch exception and return None/Empty
            assert res == [] or res is None


# --- i18n.py ---
def test_i18n_finalize_coverage():
    """Test detect_preferred_language with missing key in Spanish (hitting line 740)."""
    with patch.dict(os.environ, {"LC_ALL": "", "LC_MESSAGES": "", "LANG": ""}):
        with patch("locale.getlocale", side_effect=Exception("fail")):
            with patch("locale.getdefaultlocale", return_value=("fr_FR", "UTF-8")):
                assert detect_preferred_language() == "en"


def test_i18n_whitespace_env():
    """Test line 718: empty string after strip in environment variable."""
    with patch.dict(os.environ, {"LC_ALL": "   ", "LC_MESSAGES": "", "LANG": ""}):
        # Priority 2 loop, _map will return None for "   "
        # Then system locale fallback
        with patch("locale.getlocale", return_value=(None, None)):
            with patch("locale.getdefaultlocale", return_value=("es_ES", "UTF-8")):
                assert detect_preferred_language() == "es"


# --- updater.py ---


def test_updater_should_drop_edge():
    """Test internal should_drop logic via render (lines 312, 314)."""
    notes = "- View in Spanish\n- https://example.com\n- Valid Item"
    # render calls _extract_release_items which calls should_drop
    summary = render_update_summary_for_cli(
        current_version="1.0",
        latest_version="2.0",
        release_notes=notes,
        release_url="url",
        published_at="date",
        lang="en",
        t_fn=lambda k, *a: k,
    )
    # "View in Spanish" and URL should be dropped
    assert "View in Spanish" not in summary
    assert "https://example.com" not in summary
    assert "Valid Item" in summary


def test_check_for_updates_failure():
    """Test check_for_updates when fetch fails (line 204)."""
    with patch("redaudit.core.updater.fetch_latest_version", return_value=None):
        res = check_for_updates(MagicMock(), "en")
        assert res[0] is False


def test_updater_complex_wrapping():
    """Test long line wrapping and truncation (lines 555-556, 559, 562-564)."""
    # Trigger segments is empty by patching textwrap.wrap
    with patch("textwrap.wrap", return_value=[]):
        res = format_release_notes_for_cli("Some notes", width=10)
        assert "Some notes" in res

    # Trigger segments[1:] (line 559)
    # Use many words to force wrap at 60
    notes = " ".join(["word"] * 30)
    res = format_release_notes_for_cli(notes, width=60)
    assert "\n" in res

    # Trigger max_lines truncation (562-564)
    notes = "L1\nL2\nL3\nL4\nL5"
    res = format_release_notes_for_cli(notes, max_lines=2)
    assert "..." in res


def test_restart_self_scenarios():
    """Test restart_self branches (lines 586, 594, 603, 611, 613)."""
    with patch("sys.argv", []):
        assert restart_self() is False

    with patch("sys.argv", ["redaudit"]):
        with patch("os.execvp", side_effect=Exception("execvp fail")):
            with patch("shutil.which", return_value=None):
                with patch("os.path.isfile", return_value=False):
                    assert restart_self(logger=MagicMock()) is False

        with patch("os.execvp", side_effect=Exception("execvp fail")):
            with patch("shutil.which", return_value="/usr/bin/redaudit"):
                with patch(
                    "os.execv",
                    side_effect=[Exception("execv resolved fail"), Exception("python execv fail")],
                ):
                    with patch("os.path.isfile", return_value=True):
                        assert restart_self(logger=MagicMock()) is False


def test_compute_tree_diff_exceptions():
    """Test compute_tree_diff exception (line 682-684)."""
    with patch("os.path.isdir", return_value=True):
        with patch("redaudit.core.updater._iter_files", return_value=["file1"]):
            with patch("os.path.getsize", side_effect=Exception("io error")):
                diff = compute_tree_diff("/old", "/new")
                assert "file1" in diff["modified"]


def test_inject_lang_fail():
    """Test _inject_default_lang with missing file (line 699)."""
    with patch("os.path.isfile", return_value=False):
        assert _inject_default_lang("/no/file", "en") is False


@patch("shutil.which", return_value="/usr/bin/git")
@patch("subprocess.Popen")
@patch("redaudit.core.updater.CommandRunner")
def test_perform_git_update_installer_fail(MockCR, mock_popen, mock_which):
    """Test perform_git_update with installer bash failure (line 938)."""
    process = MagicMock()
    process.stdout.readline.side_effect = ["Cloning...", ""]
    process.poll.return_value = 0
    process.wait.return_value = 0
    process.returncode = 0
    mock_popen.return_value = process

    runner = MockCR.return_value
    runner.check_output.return_value = "abc"
    runner.run.return_value = MagicMock(returncode=1, stderr="bash error")

    with patch("os.geteuid", return_value=0):
        with patch("tempfile.mkdtemp", return_value="/tmp/red"):
            with patch("os.path.isdir", side_effect=lambda p: "redaudit" in p):
                with patch("shutil.rmtree"):
                    with patch("shutil.copytree"):
                        with patch("os.path.isfile", return_value=True):
                            with patch("os.chmod"):
                                logger = MagicMock()
                                # We ensure manual fallback triggers logging
                                # By failing early in Manual install step (948) so we don't need deeper mocks
                                with patch("os.path.isdir", side_effect=[True, False]):
                                    perform_git_update("/repo", logger=logger, t_fn=lambda k, *a: k)
                                    assert any(
                                        "bash error" in str(call)
                                        for call in logger.warning.call_args_list
                                    )


@patch("shutil.which", return_value="/usr/bin/git")
@patch("subprocess.Popen")
@patch("redaudit.core.updater.CommandRunner")
def test_perform_git_update_verification_fail_rollback(MockCR, mock_popen, mock_which):
    """Test perform_git_update verification failure and rollback (lines 1164-1165, 1171-1172, 1177-1178, 1185-1207)."""
    process = MagicMock()
    process.stdout.readline.side_effect = ["Cloning...", ""]
    process.poll.return_value = 0
    process.wait.return_value = 0
    process.returncode = 0
    mock_popen.return_value = process

    runner = MockCR.return_value
    runner.check_output.return_value = "abc"
    runner.run.return_value = MagicMock(returncode=0)

    # Helper side_effect for os.path.isdir to support logic flow
    mock_isdir_iter = iter([True, True, True, True, False])

    def isdir_side_effect(path):
        try:
            val = next(mock_isdir_iter)
            return val
        except StopIteration:
            return False

    with patch("os.geteuid", return_value=0):
        with patch("tempfile.mkdtemp", return_value="/tmp/red"):
            with patch("shutil.rmtree"):
                with patch("shutil.copytree"):
                    with patch("os.walk", return_value=[]):
                        with patch("os.chmod"):
                            with patch("os.path.isdir", side_effect=isdir_side_effect):
                                with patch("os.path.isfile", return_value=True):
                                    with patch("os.rename"):
                                        with patch("os.path.exists", return_value=True):
                                            with patch(
                                                "redaudit.core.updater._inject_default_lang"
                                            ):
                                                success, msg = perform_git_update(
                                                    "/repo", t_fn=lambda k, *args: k
                                                )
                                                assert success is False
                                                assert "Module not installed" in msg


@patch("shutil.which", return_value="/usr/bin/git")
@patch("subprocess.Popen")
@patch("redaudit.core.updater.CommandRunner")
def test_perform_git_update_home_swap_fail(MockCR, mock_popen, mock_which):
    """Test home folder swap failure and rollback (lines 1142, 1130-1139)."""
    process = MagicMock()
    process.stdout.readline.side_effect = ["Cloning...", ""]
    process.poll.return_value = 0
    process.wait.return_value = 0
    process.returncode = 0
    mock_popen.return_value = process

    runner = MockCR.return_value
    # Fix: second return must match first for verification pass
    runner.check_output.side_effect = ["abc", "abc", ""]
    runner.run.return_value = MagicMock(returncode=0)

    with patch("os.geteuid", return_value=0):
        with patch("tempfile.mkdtemp", return_value="/tmp/red"):
            with patch("shutil.rmtree"):
                with patch("shutil.copytree"):
                    with patch("os.path.isdir", return_value=True):
                        with patch("os.path.isfile", return_value=True):
                            with patch("os.path.exists", return_value=True):
                                # Renames: backup system, activate system, backup home, activate home (FAIL)
                                with patch(
                                    "os.rename",
                                    side_effect=[None, None, None, Exception("HOME_SWAP_FAIL")],
                                ):
                                    with (
                                        patch("os.chmod"),
                                        patch("redaudit.core.updater._inject_default_lang"),
                                    ):
                                        success, msg = perform_git_update(
                                            "/repo", t_fn=lambda k, *args: k
                                        )
                                        assert success is False
                                        assert "HOME_SWAP_FAIL" in msg


@patch("shutil.which", return_value="/usr/bin/git")
@patch("subprocess.Popen")
@patch("redaudit.core.updater.CommandRunner")
def test_perform_git_update_fix_ownership_fail(MockCR, mock_popen, mock_which):
    """Test ownership fix failure (lines 1147-1155)."""
    process = MagicMock()
    process.stdout.readline.side_effect = ["Cloning...", ""]
    process.poll.return_value = 0
    process.wait.return_value = 0
    process.returncode = 0
    mock_popen.return_value = process

    runner = MockCR.return_value
    runner.check_output.side_effect = ["abc", "abc", ""]
    runner.run.return_value = MagicMock(returncode=0)

    with patch("os.geteuid", return_value=0):
        with patch("pwd.getpwnam") as mock_pwd:
            mock_pwd.return_value.pw_uid = 1000
            mock_pwd.return_value.pw_gid = 1000
            with patch.dict(os.environ, {"SUDO_USER": "user"}):
                with patch("tempfile.mkdtemp", return_value="/tmp/red"):
                    with patch("shutil.rmtree"):
                        with patch("shutil.copytree"):
                            with patch("os.path.isdir", return_value=True):
                                with patch("os.path.isfile", return_value=True):
                                    with patch("os.rename", return_value=None):
                                        # Use return_value to ensure infinite supply of iterators
                                        with patch(
                                            "os.walk", return_value=[("/root", ["dir"], ["file"])]
                                        ):
                                            with patch("os.chmod"):
                                                with patch(
                                                    "os.chown", side_effect=Exception("chown fail")
                                                ):
                                                    with patch(
                                                        "redaudit.core.updater._inject_default_lang"
                                                    ):
                                                        logger = MagicMock()
                                                        success, _ = perform_git_update(
                                                            "/repo",
                                                            logger=logger,
                                                            t_fn=lambda k, *a: k,
                                                        )
                                                        assert success is True
                                                        assert any(
                                                            "chown fail" in str(call)
                                                            for call in logger.warning.call_args_list
                                                        )


def test_notice_terminal_size_fail():
    """Test Terminal size Exception in notice (line 1363-1364, 1388-1389)."""
    with patch("shutil.get_terminal_size", side_effect=Exception("no term")):
        _show_restart_terminal_notice(t_fn=lambda k, *a: k)


def test_pause_non_tty():
    """Test pause in non-tty (line 1400-1402, 1403-1404)."""
    with patch("sys.stdin", None):
        with patch("time.sleep") as mock_sleep:
            _pause_for_restart_terminal(t_fn=lambda k, *a: k)
            mock_sleep.assert_called_once()

    with patch("sys.stdin", MagicMock()):
        with patch("sys.stdin.isatty", return_value=False):
            with patch("time.sleep", side_effect=Exception("sleep fail")):
                _pause_for_restart_terminal(t_fn=lambda k, *a: k)


def test_perform_git_update_staging_verify_fail():
    """Test staging verification failure (line 971-972)."""
    with patch("os.geteuid", return_value=0):
        with patch("tempfile.mkdtemp", return_value="/tmp/red"):
            with patch("shutil.rmtree"):
                with patch("shutil.copytree"):
                    with patch("os.path.isdir", return_value=True):
                        with patch(
                            "redaudit.core.updater.compute_tree_diff",
                            side_effect=Exception("diff fail"),
                        ):
                            with patch("os.path.exists", return_value=False):
                                perform_git_update("/repo", t_fn=lambda k, *args: k)
