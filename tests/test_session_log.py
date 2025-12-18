#!/usr/bin/env python3
"""
Tests for session_log module.
"""

import io
import unittest

from redaudit.utils.session_log import TeeStream


class TestTeeStream(unittest.TestCase):
    def test_lines_mode_ignores_partial_writes(self):
        terminal = io.StringIO()
        log = io.StringIO()
        stream = TeeStream(terminal, log, mode="lines")

        stream.write("progress 10%")
        self.assertEqual(log.getvalue(), "")
        self.assertEqual(terminal.getvalue(), "progress 10%")

        stream.write("\n")
        self.assertEqual(log.getvalue(), "progress 10%\n")

    def test_lines_mode_drops_carriage_return_frames(self):
        terminal = io.StringIO()
        log = io.StringIO()
        stream = TeeStream(terminal, log, mode="lines")

        # Simulate progress redraws that rewrite the same line using carriage returns.
        stream.write("frame1\rframe2\rframe3")
        self.assertEqual(log.getvalue(), "")

        stream.write("\n")
        self.assertEqual(log.getvalue(), "frame3\n")

    def test_lines_mode_prefixes_stderr_lines(self):
        terminal = io.StringIO()
        log = io.StringIO()
        stream = TeeStream(terminal, log, prefix="[stderr] ", mode="lines")

        stream.write("oops\n")
        self.assertEqual(log.getvalue(), "[stderr] oops\n")
        self.assertEqual(terminal.getvalue(), "oops\n")

    def test_raw_mode_logs_every_write(self):
        terminal = io.StringIO()
        log = io.StringIO()
        stream = TeeStream(terminal, log, mode="raw")

        stream.write("a")
        stream.write("b")
        stream.write("\n")
        self.assertEqual(log.getvalue(), "ab\n")
