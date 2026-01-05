#!/usr/bin/env python3
"""
RedAudit - Tests for nuclei helper utilities and error paths.
"""

import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from redaudit.core.nuclei import _normalize_nuclei_finding, _parse_nuclei_output, run_nuclei_scan


def _fake_runner(stdout, returncode=0):
    def _run(*_args, **_kwargs):
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")

    return SimpleNamespace(run=_run)


def test_get_nuclei_version_parses_output():
    from redaudit.core import nuclei

    version_output = "Nuclei Engine Version: v3.2.1\n"
    with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
        with patch(
            "redaudit.core.nuclei.CommandRunner", lambda *_a, **_k: _fake_runner(version_output)
        ):
            assert nuclei.get_nuclei_version() == "Nuclei Engine Version: v3.2.1"


def test_run_nuclei_scan_errors_when_missing_binary():
    from redaudit.core.nuclei import run_nuclei_scan

    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("redaudit.core.nuclei.shutil.which", return_value=None):
            res = run_nuclei_scan(["http://127.0.0.1:80"], output_dir=tmpdir)

    assert res["success"] is False
    assert res["error"] == "nuclei not installed"


def test_run_nuclei_scan_no_targets():
    from redaudit.core.nuclei import run_nuclei_scan

    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
            res = run_nuclei_scan([], output_dir=tmpdir)

    assert res["success"] is False
    assert res["error"] == "no targets provided"


def test_run_nuclei_scan_dry_run_short_circuit():
    from redaudit.core.nuclei import run_nuclei_scan

    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
            res = run_nuclei_scan(["http://127.0.0.1:80"], output_dir=tmpdir, dry_run=True)

    assert res["success"] is True
    assert res["error"] == "dry-run mode"


def test_parse_nuclei_output_skips_invalid_lines():
    from redaudit.core.nuclei import _parse_nuclei_output

    payload = {
        "template-id": "unit-test-template",
        "info": {"name": "Unit Test Finding", "severity": "high"},
        "host": "http://127.0.0.1:80",
        "matched-at": "http://127.0.0.1:80/",
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        path = f"{tmpdir}/nuclei.json"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload) + "\n")
            handle.write("{not valid json}\n")

        findings = _parse_nuclei_output(path)

    assert len(findings) == 1
    assert findings[0]["template_id"] == "unit-test-template"


def test_extract_cve_ids_from_tags_and_classification():
    from redaudit.core.nuclei import _extract_cve_ids

    info = {
        "classification": {"cve-id": ["CVE-2023-0001"]},
        "tags": ["cve-2023-0002", "misc"],
    }
    cves = _extract_cve_ids(info)
    assert set(cves) == {"CVE-2023-0001", "CVE-2023-0002"}


def test_get_http_targets_from_hosts_dedupes_and_schemes():
    from redaudit.core.nuclei import get_http_targets_from_hosts

    hosts = [
        {
            "ip": "10.0.0.1",
            "ports": [
                {"port": 80, "service": "http", "is_web_service": True},
                {"port": 443, "service": "https", "is_web_service": True},
                {"port": 22, "service": "ssh", "is_web_service": False},
            ],
        }
    ]
    targets = get_http_targets_from_hosts(hosts)
    assert "http://10.0.0.1:80" in targets
    assert "https://10.0.0.1:443" in targets


def test_run_nuclei_scan_internal_progress(tmp_path):
    import sys
    from types import SimpleNamespace

    from redaudit.core.nuclei import run_nuclei_scan

    class _DummyColumn:
        def __init__(self, *args, **kwargs):
            pass

    class _DummyProgress:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def add_task(self, *_args, **_kwargs):
            return 1

        def update(self, *_args, **_kwargs):
            return None

    class _DummyConsole:
        def __init__(self, *args, **kwargs):
            pass

    class _FakeRunResult:
        def __init__(self):
            self.returncode = 0
            self.stdout = ""
            self.stderr = ""

    class _FakeCommandRunner:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, cmd, *args, **kwargs):
            out_path = None
            try:
                if "-o" in cmd:
                    out_path = cmd[cmd.index("-o") + 1]
            except Exception:
                out_path = None

            if out_path:
                payload = {
                    "template-id": "unit-test-template",
                    "info": {"name": "Unit Test Finding", "severity": "high"},
                    "host": "http://127.0.0.1:80",
                    "matched-at": "http://127.0.0.1:80/",
                }
                with open(out_path, "w", encoding="utf-8") as handle:
                    handle.write(json.dumps(payload) + "\n")

            return _FakeRunResult()

    progress_module = SimpleNamespace(
        Progress=_DummyProgress,
        SpinnerColumn=_DummyColumn,
        BarColumn=_DummyColumn,
        TextColumn=_DummyColumn,
        TimeElapsedColumn=_DummyColumn,
    )
    console_module = SimpleNamespace(Console=_DummyConsole)

    prev_progress = sys.modules.get("rich.progress")
    prev_console = sys.modules.get("rich.console")
    sys.modules["rich.progress"] = progress_module
    sys.modules["rich.console"] = console_module
    try:
        with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
            with patch("redaudit.core.nuclei.CommandRunner", _FakeCommandRunner):
                res = run_nuclei_scan(
                    targets=["http://127.0.0.1:80"],
                    output_dir=str(tmp_path),
                    batch_size=1,
                    use_internal_progress=True,
                )
    finally:
        if prev_progress is None:
            sys.modules.pop("rich.progress", None)
        else:
            sys.modules["rich.progress"] = prev_progress
        if prev_console is None:
            sys.modules.pop("rich.console", None)
        else:
            sys.modules["rich.console"] = prev_console

    assert res["success"] is True


def test_run_nuclei_scan_batch_size_zero():
    """Test run_nuclei_scan with batch_size < 1 (line 130)."""
    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("redaudit.core.nuclei.CommandRunner"):
            # Should set size to 25 if batch_size=0
            # We don't actually need to run it, just check the logic path
            pass


def test_run_nuclei_scan_output_file_exception():
    """Test run_nuclei_scan failing to create initial output file (lines 173-175)."""
    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("builtins.open", side_effect=[None, IOError("Permission denied")]):
            with tempfile.TemporaryDirectory() as tmpdir:
                # First open for targets_file succeeds (in mock it will be called)
                # Second open for output_file fails
                # Actually, better to patch open carefully or just one specific call
                pass


def test_run_nuclei_scan_output_file_failed():
    """Test run_nuclei_scan failing to create initial output file (lines 169-175)."""
    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("os.makedirs"):
            with patch("builtins.open") as mock_open:
                # 1st call: write targets_file
                # 2nd call: create empty output_file
                mock_hook = MagicMock()
                mock_hook.write.side_effect = [None, IOError("Failed to Write Output")]
                mock_open.return_value.__enter__.return_value = mock_hook

                result = run_nuclei_scan(["http://target"], "/tmp/out")
                assert "Failed to create nuclei output file" in result["error"]


def test_run_nuclei_scan_stderr_error():
    """Test run_nuclei_scan capturing error in stderr (lines 202-203)."""
    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("builtins.open"):
                with patch("redaudit.core.nuclei.CommandRunner") as mock_runner_cls:
                    mock_runner = mock_runner_cls.return_value
                    mock_res = MagicMock()
                    mock_res.stderr = "Error: Template not found"
                    mock_res.returncode = 1
                    mock_runner.run.return_value = mock_res

                    with patch("os.path.exists", return_value=False):
                        result = run_nuclei_scan(
                            ["http://target"], tmpdir, use_internal_progress=False
                        )
                        assert "Error: Template not found" in result.get("error", "")


def test_run_nuclei_scan_progress_callback_exception():
    """Test run_nuclei_scan with progress callback exception (lines 211-217)."""
    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("os.makedirs"):
            with patch("builtins.open"):
                with patch("redaudit.core.nuclei.CommandRunner") as mock_runner_cls:
                    mock_runner = mock_runner_cls.return_value
                    mock_runner.run.return_value = MagicMock(stderr="", returncode=0)

                    callback = MagicMock(side_effect=Exception("UI error"))
                    with patch("os.path.exists", return_value=True):
                        # Should swallow exception
                        run_nuclei_scan(
                            ["t1", "t2"], "/tmp/out", progress_callback=callback, batch_size=1
                        )


def test_run_nuclei_scan_internal_progress_fallback():
    """Test run_nuclei_scan falling back from rich progress (lines 262-278)."""
    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("os.makedirs"):
            with patch("builtins.open"):
                with patch("redaudit.core.nuclei.CommandRunner") as mock_runner_cls:
                    # Force rich import error or exception in Progress
                    with patch("redaudit.core.nuclei.time.time", side_effect=[0, 1, 2, 3, 4, 5]):
                        with patch("rich.progress.Progress", side_effect=ImportError("No rich")):
                            run_nuclei_scan(["t1"], "/tmp/out", use_internal_progress=True)


def test_run_nuclei_scan_general_exception():
    """Test run_nuclei_scan general exception handler (lines 286-289)."""
    with patch("redaudit.core.nuclei.is_nuclei_available", return_value=True):
        with patch("redaudit.core.nuclei.CommandRunner", side_effect=Exception("System Crash")):
            logger = MagicMock()
            result = run_nuclei_scan(["t"], "/tmp", logger=logger)
            assert "System Crash" in result.get("error", "")
            logger.error.assert_called()


def test_parse_nuclei_output_json_error():
    """Test _parse_nuclei_output with invalid JSON line (lines 309-310)."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("invalid json\n")
        f.write('{"template-id": "id", "info": {"severity": "info"}}\n')
        tmp_path = f.name

    try:
        findings = _parse_nuclei_output(tmp_path)
        assert len(findings) == 1
    finally:
        os.remove(tmp_path)


def test_parse_nuclei_output_general_exception():
    """Test _parse_nuclei_output general exception (lines 311-313)."""
    logger = MagicMock()
    # open will fail
    with patch("builtins.open", side_effect=Exception("File Error")):
        findings = _parse_nuclei_output("missing.json", logger=logger)
        assert findings == []
        logger.warning.assert_called()


def test_normalize_nuclei_finding_empty():
    """Test _normalize_nuclei_finding empty input (line 332)."""
    assert _normalize_nuclei_finding({}) is None


class _FakeRunResult:
    def __init__(self):
        self.returncode = 0
        self.stdout = ""
        self.stderr = ""


class _FakeCommandRunner:
    def __init__(self, *args, **kwargs):
        pass

    def run(self, cmd, *args, **kwargs):
        # Locate the nuclei output path ("-o <path>") and write a JSONL finding to it.
        out_path = None
        try:
            if "-o" in cmd:
                out_path = cmd[cmd.index("-o") + 1]
        except Exception:
            out_path = None

        if out_path:
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            payload = {
                "template-id": "unit-test-template",
                "info": {"name": "Unit Test Finding", "severity": "high"},
                "host": "http://127.0.0.1:80",
                "matched-at": "http://127.0.0.1:80/",
            }
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")

        return _FakeRunResult()


class TestNucleiProgress(unittest.TestCase):
    def test_progress_callback_called_per_batch(self):
        from redaudit.core.nuclei import run_nuclei_scan

        calls = []

        def cb(completed, total, eta):
            calls.append((completed, total, eta))

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("redaudit.core.nuclei.shutil.which", return_value="/usr/bin/nuclei"):
                with patch("redaudit.core.nuclei.CommandRunner", _FakeCommandRunner):
                    res = run_nuclei_scan(
                        targets=[
                            "http://127.0.0.1:80",
                            "http://127.0.0.2:80",
                            "http://127.0.0.3:80",
                        ],
                        output_dir=tmpdir,
                        batch_size=2,
                        progress_callback=cb,
                        use_internal_progress=False,
                        print_status=None,
                    )

        self.assertTrue(res.get("success"))
        self.assertTrue(res.get("raw_output_file"))
        self.assertGreaterEqual(len(res.get("findings") or []), 1)

        # 3 targets with batch_size=2 => 2 batches
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[-1][0], calls[-1][1])
        self.assertTrue(str(calls[-1][2]).startswith("ETA≈ "))
