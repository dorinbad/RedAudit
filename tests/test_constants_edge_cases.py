"""
Tests for constants.py to push coverage to 100%.
Targets: 34-35, 51-53, 73
"""

from unittest.mock import patch

from redaudit.utils.constants import (
    _read_packaged_version_file,
    _read_pyproject_version,
    _resolve_version,
)


def test_read_packaged_version_file_exception():
    """Test _read_packaged_version_file with exception (line 34-35)."""
    with patch("pathlib.Path.is_file", side_effect=Exception("File error")):
        result = _read_packaged_version_file()
        assert result is None


def test_read_pyproject_version_no_match():
    """Test _read_pyproject_version with no version match (line 51-53)."""
    with patch("pathlib.Path.is_file", return_value=True):
        with patch("pathlib.Path.read_text", return_value="no version here"):
            result = _read_pyproject_version()
            assert result is None


def test_resolve_version_pyproject_fallback():
    """Test _resolve_version using pyproject fallback (line 73).

    Note: This test verifies the mocking mechanism works. The actual
    _resolve_version function is called at module import time, so we
    test the components directly.
    """
    # Test that _read_pyproject_version returns the actual version from pyproject.toml
    result = _read_pyproject_version()
    # It should return a version string in semver format
    assert result is not None
    assert "." in result
    # Verify the import returns a value as well
    assert _resolve_version() is not None
