#!/usr/bin/env python3
"""
Tests for SessionLogger helpers.
"""

import sys

from redaudit.utils.session_log import SessionLogger, start_session_log, stop_session_log


def test_session_logger_start_stop_creates_clean_log(tmp_path):
    logger = SessionLogger(str(tmp_path), session_name="unit", mode="lines")
    original_stdout = sys.stdout
    original_stderr = sys.stderr

    assert logger.start() is True
    assert sys.stdout is logger.tee_stdout
    assert sys.stderr is logger.tee_stderr

    print("\x1b[31mhello\x1b[0m")
    clean_path = logger.stop()

    assert sys.stdout is original_stdout
    assert sys.stderr is original_stderr
    assert clean_path is not None

    raw_path = tmp_path / "session_logs" / "session_unit.log"
    txt_path = tmp_path / "session_logs" / "session_unit.txt"
    assert raw_path.exists()
    assert txt_path.exists()
    assert "\x1b" not in txt_path.read_text(encoding="utf-8")


def test_session_logger_mode_off_skips_logging(tmp_path):
    logger = SessionLogger(str(tmp_path), session_name="off", mode="off")
    original_stdout = sys.stdout

    assert logger.start() is False
    assert sys.stdout is original_stdout


def test_session_logger_start_handles_failure(tmp_path, monkeypatch):
    logger = SessionLogger(str(tmp_path), session_name="fail")

    def _boom(*_args, **_kwargs):
        raise OSError("nope")

    from pathlib import Path

    monkeypatch.setattr(Path, "mkdir", _boom)
    assert logger.start() is False


def test_start_stop_session_log_roundtrip(tmp_path):
    assert start_session_log(str(tmp_path), session_name="roundtrip", mode="lines") is True
    print("hello")
    result = stop_session_log()
    assert result is not None
    assert result.endswith(".txt")
