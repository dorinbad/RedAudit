import unittest
from unittest.mock import MagicMock, patch, ANY
import sys

# Mock Impacket modules before importing SMBScanner
sys.modules["impacket"] = MagicMock()
sys.modules["impacket.smbconnection"] = MagicMock()
sys.modules["impacket.smb"] = MagicMock()
sys.modules["impacket.dcerpc"] = MagicMock()
sys.modules["impacket.dcerpc.v5"] = MagicMock()

from redaudit.core.auth_smb import SMBScanner, SMBConnectionError, IMPACKET_AVAILABLE
from redaudit.core.credentials import Credential


@patch("redaudit.core.auth_smb.IMPACKET_AVAILABLE", True)
class TestSMBScanner(unittest.TestCase):
    def setUp(self):
        self.credential = Credential(username="Admin", password="Password123", domain="WORKGROUP")

    def test_init_raises_if_missing_dependency(self):
        # We need to simulate IMPACKET_AVAILABLE = False
        with patch("redaudit.core.auth_smb.IMPACKET_AVAILABLE", False):
            with self.assertRaises(ImportError):
                SMBScanner(self.credential)

    @patch("redaudit.core.auth_smb.SMBConnection")
    def test_connect_success(self, MockSMBConnection):
        # Setup mock instance
        mock_conn = MockSMBConnection.return_value

        scanner = SMBScanner(self.credential)
        result = scanner.connect("192.168.1.50")

        self.assertTrue(result)
        MockSMBConnection.assert_called_with(
            "192.168.1.50", "192.168.1.50", sess_port=445, timeout=15
        )
        mock_conn.login.assert_called_with("Admin", "Password123", domain="WORKGROUP")

    @patch("redaudit.core.auth_smb.SMBConnection")
    def test_connect_failure(self, MockSMBConnection):
        mock_conn = MockSMBConnection.return_value
        mock_conn.login.side_effect = Exception("Logon failure")

        scanner = SMBScanner(self.credential)
        with self.assertRaises(SMBConnectionError):
            scanner.connect("192.168.1.50")

    @patch("redaudit.core.auth_smb.SMBConnection")
    def test_gather_host_info(self, MockSMBConnection):
        mock_conn = MockSMBConnection.return_value
        mock_conn.getServerOS.return_value = "Windows Server 2019"
        mock_conn.getServerOSMajor.return_value = "10"
        mock_conn.getServerOSMinor.return_value = "0"
        mock_conn.getServerDomain.return_value = "CONTOSO"
        mock_conn.getServerName.return_value = "DC01"

        # Mock shares
        # Impacket listShares returns list of dict-like or objects you access with keys
        # The code implementation expects dictionary usage with 'shi1_netname'
        mock_share1 = {
            "shi1_netname": b"ADMIN$\x00",
            "shi1_remark": b"Remote Admin\x00",
            "shi1_type": 2147483648,
        }
        mock_share2 = {
            "shi1_netname": b"C$\x00",
            "shi1_remark": b"Default Share\x00",
            "shi1_type": 0,
        }
        mock_conn.listShares.return_value = [mock_share1, mock_share2]

        scanner = SMBScanner(self.credential)
        scanner.conn = mock_conn  # Simulate connected
        scanner.target_ip = "192.168.1.50"

        info = scanner.gather_host_info()

        self.assertEqual(info.os_name, "Windows Server 2019")
        self.assertEqual(info.os_version, "10.0")
        self.assertEqual(info.domain, "CONTOSO")
        self.assertEqual(len(info.shares), 2)
        self.assertEqual(info.shares[0]["name"], "ADMIN$")
