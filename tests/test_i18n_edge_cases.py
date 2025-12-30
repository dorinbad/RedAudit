"""Quick tests for i18n.py missing lines 718, 740"""

from redaudit.utils.i18n import get_text


def test_i18n_missing_key():
    """Test get_text with missing key (line 718)."""
    result = get_text("nonexistent_key_12345", "en")
    assert "nonexistent_key_12345" in result


def test_i18n_missing_key_es():
    """Test get_text with missing key in Spanish (line 740)."""
    result = get_text("nonexistent_key_67890", "es")
    assert "nonexistent_key_67890" in result
