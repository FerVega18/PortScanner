"""Verify how PortScanner interprets simulated TCP connection results."""

import unittest
from unittest.mock import patch

from scanner import PortScanner


class PortScannerTests(unittest.TestCase):
    """Check the state reported for a single TCP connection attempt."""

    @patch("scanner.socket.getservbyport", return_value="http")
    @patch("scanner.socket.socket")
    def test_successful_connection_marks_port_open(
        self, mock_socket_class, mock_service_lookup
    ):
        """
        Verify that a successful TCP connection is reported as open.

        Scenario:
            The simulated socket returns 0 from connect_ex(), and the service
            lookup returns "http" for TCP port 80.

        Expected result:
            The result identifies port 80 and reports its state as "open".
        """
        mock_socket = mock_socket_class.return_value
        mock_socket.connect_ex.return_value = 0

        scanner = PortScanner()
        result = scanner.scan_port("127.0.0.1", 80)

        self.assertEqual(result["port"], 80)
        self.assertEqual(result["state"], "open")