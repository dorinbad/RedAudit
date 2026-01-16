import unittest
from unittest.mock import patch, MagicMock
from redaudit.core.rustscan import (
    is_rustscan_available,
    get_rustscan_version,
    run_rustscan,
    run_rustscan_discovery_only,
    run_rustscan_multi,
    _parse_rustscan_ports,
    _parse_rustscan_greppable,
    _parse_rustscan_greppable_map,
)


class TestRustScan(unittest.TestCase):
    def test_is_rustscan_available_true(self):
        with patch("shutil.which", return_value="/usr/bin/rustscan"):
            self.assertTrue(is_rustscan_available())

    def test_is_rustscan_available_false(self):
        with patch("shutil.which", return_value=None):
            self.assertFalse(is_rustscan_available())

    def test_get_rustscan_version(self):
        with patch("shutil.which", return_value="/usr/bin/rustscan"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                mock_run.return_value.stdout = "rustscan 1.2.3\n"
                self.assertEqual(get_rustscan_version(), "1.2.3")

    def test_parse_rustscan_ports(self):
        stdout = "Open 10.10.10.10:80\nOpen 10.10.10.10:443\n"
        ports = _parse_rustscan_ports(stdout)
        self.assertEqual(ports, [80, 443])

    def test_parse_rustscan_greppable(self):
        stdout = "10.10.10.10 -> [80,443]\n192.168.1.1 -> [22,80]\n"
        ports = _parse_rustscan_greppable(stdout)
        self.assertEqual(ports, [22, 80, 443])

    def test_parse_rustscan_greppable_map(self):
        stdout = "10.10.10.10 -> [80,443]\n192.168.1.1 -> [22,80]\n"
        parsed = _parse_rustscan_greppable_map(stdout)
        self.assertEqual(parsed.get("10.10.10.10"), [80, 443])
        self.assertEqual(parsed.get("192.168.1.1"), [22, 80])

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan.CommandRunner")
    def test_run_rustscan(self, mock_runner_cls, _):
        mock_runner = mock_runner_cls.return_value
        mock_runner.run.return_value.returncode = 0
        mock_runner.run.return_value.stdout = "Open 127.0.0.1:80\n"
        mock_runner.run.return_value.timed_out = False  # Explicitly False

        res = run_rustscan("127.0.0.1", ports=[80, 443])
        self.assertTrue(res["success"])
        self.assertEqual(res["ports"], [80])

        # Verify args passed
        args, _ = mock_runner.run.call_args
        cmd = args[0]
        self.assertIn("-p", cmd)
        self.assertIn("80,443", cmd)
        self.assertIn("--ulimit", cmd)

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan.CommandRunner")
    def test_run_rustscan_discovery_only(self, mock_runner_cls, _):
        mock_runner = mock_runner_cls.return_value
        mock_runner.run.return_value.returncode = 0
        mock_runner.run.return_value.stdout = "127.0.0.1 -> [80]\n"
        mock_runner.run.return_value.timed_out = False

        ports, err = run_rustscan_discovery_only("127.0.0.1", ports=[80])
        self.assertEqual(ports, [80])
        self.assertIsNone(err)

        # Verify -g flag
        args, _ = mock_runner.run.call_args
        cmd = args[0]
        self.assertIn("-g", cmd)
        self.assertIn("-p", cmd)

    @patch("redaudit.core.rustscan.is_rustscan_available", return_value=True)
    @patch("redaudit.core.rustscan.CommandRunner")
    def test_run_rustscan_multi(self, mock_runner_cls, _):
        mock_runner = mock_runner_cls.return_value
        mock_runner.run.return_value.returncode = 0
        mock_runner.run.return_value.stdout = "192.168.1.1 -> [80]\n192.168.1.2 -> [443]\n"
        mock_runner.run.return_value.timed_out = False

        res_map, err = run_rustscan_multi(["192.168.1.1", "192.168.1.2"])
        self.assertIsNone(err)
        self.assertEqual(res_map["192.168.1.1"], [80])
        self.assertEqual(res_map["192.168.1.2"], [443])

        # Verify targets joined
        args, _ = mock_runner.run.call_args
        cmd = args[0]
        self.assertIn("192.168.1.1,192.168.1.2", cmd)


if __name__ == "__main__":
    unittest.main()
