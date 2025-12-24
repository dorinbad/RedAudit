import os
import pytest
import pwd
from unittest.mock import MagicMock, patch
from redaudit.utils.paths import (
    get_invoking_user,
    get_reports_home_dir,
    get_invoking_home_dir,
    expand_user_path,
    get_documents_dir,
    get_default_reports_base_dir,
    resolve_invoking_user_owner,
    maybe_chown_to_invoking_user,
    maybe_chown_tree_to_invoking_user,
)


def test_get_invoking_user():
    with (
        patch("redaudit.utils.paths._is_root", return_value=True),
        patch.dict(os.environ, {"SUDO_USER": "testuser"}),
    ):
        assert get_invoking_user() == "testuser"

    with patch("redaudit.utils.paths._is_root", return_value=False):
        assert get_invoking_user() is None


def test_get_reports_home_dir():
    with (
        patch("redaudit.utils.paths.get_invoking_user", return_value="user1"),
        patch("redaudit.utils.paths._resolve_home_dir_for_user", return_value="/home/user1"),
    ):
        assert get_reports_home_dir() == "/home/user1"

    with (
        patch("redaudit.utils.paths.get_invoking_user", return_value=None),
        patch(
            "redaudit.utils.paths._get_preferred_human_home_under_home", return_value="/home/kali"
        ),
    ):
        assert get_reports_home_dir() == "/home/kali"


def test_get_invoking_home_dir():
    with patch("redaudit.utils.paths.get_invoking_user", return_value=None):
        assert get_invoking_home_dir() == os.path.expanduser("~")


def test_expand_user_path():
    with (
        patch("redaudit.utils.paths.get_invoking_user", return_value="user1"),
        patch("redaudit.utils.paths.get_invoking_home_dir", return_value="/home/user1"),
    ):
        assert expand_user_path("~/test") == "/home/user1/test"
        assert expand_user_path("~") == "/home/user1"

    assert expand_user_path("/abs") == "/abs"
    assert expand_user_path(None) == "None"


def test_get_documents_dir():
    with patch("os.path.isdir", return_value=True):
        d = get_documents_dir("/tmp")
        assert "Documents" in d or "Documentos" in d


def test_get_default_reports_base_dir():
    d = get_default_reports_base_dir()
    assert "RedAuditReports" in d


def test_resolve_invoking_user_owner():
    with (
        patch("redaudit.utils.paths._is_root", return_value=True),
        patch.dict(os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1000"}),
    ):
        assert resolve_invoking_user_owner() == (1000, 1000)


def test_maybe_chown(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("hi")
    with (
        patch("redaudit.utils.paths.resolve_invoking_user_owner", return_value=(1000, 1000)),
        patch("os.chown") as mock_chown,
    ):
        maybe_chown_to_invoking_user(str(f))
        mock_chown.assert_called_once()


def test_maybe_chown_tree(tmp_path):
    d = tmp_path / "dir"
    d.mkdir()
    (d / "file.txt").write_text("hi")
    with (
        patch("redaudit.utils.paths.resolve_invoking_user_owner", return_value=(1000, 1000)),
        patch("os.chown") as mock_chown,
    ):
        maybe_chown_tree_to_invoking_user(str(d))
        assert mock_chown.call_count >= 2
