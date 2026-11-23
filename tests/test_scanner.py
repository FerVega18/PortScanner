"""Verify how PortScanner interprets simulated TCP connection results."""

import errno
import socket
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

    @patch("scanner.socket.socket")
    def test_connection_timeout_marks_port_filtered(self, mock_socket_class):
        """
        Verify how the scanner reports a connection timeout.

        Scenario:
            The simulated socket raises socket.timeout when connect_ex()
            attempts the connection.

        Expected result:
            The scanner returns the requested port with state "filtered",
            following the current convention for a connection timeout.
        """
        mock_socket = mock_socket_class.return_value
        mock_socket.connect_ex.side_effect = socket.timeout

        scanner = PortScanner()
        result = scanner.scan_port("127.0.0.1", 80)

        self.assertEqual(result["port"], 80)
        self.assertEqual(result["state"], "filtered") 

    @patch("scanner.socket.socket")
    def test_connection_refused_marks_port_closed(self, mock_socket_class):
        """
        Verify how the scanner reports an explicit connection refusal.

        Scenario:
            The simulated socket raises ConnectionRefusedError when
            connect_ex() attempts the connection.

        Expected result:
            The result identifies port 80 and reports its state as "closed".
        """
        mock_socket = mock_socket_class.return_value
        mock_socket.connect_ex.side_effect = ConnectionRefusedError

        scanner = PortScanner()
        result = scanner.scan_port("127.0.0.1", 80)

        self.assertEqual(result["port"], 80)
        self.assertEqual(result["state"], "closed")

    @patch("scanner.socket.socket")
    def test_refused_connection_code_marks_port_closed(self, mock_socket_class):
        """
        Verify that a refusal code is reported as a closed port.

        Scenario:
            The simulated socket returns errno.ECONNREFUSED from
            connect_ex(), representing a refused TCP connection.

        Expected result:
            The result identifies port 80 and reports its state as "closed".
        """
        mock_socket = mock_socket_class.return_value
        mock_socket.connect_ex.return_value = errno.ECONNREFUSED

        scanner = PortScanner()
        result = scanner.scan_port("127.0.0.1", 80)

        self.assertEqual(result["port"], 80)
        self.assertEqual(result["state"], "closed")

    @patch("scanner.socket.socket")
    def test_timeout_code_marks_port_filtered(self, mock_socket_class):
        """
        Verify how the scanner classifies a returned timeout code.

        Scenario:
            The simulated socket returns errno.ETIMEDOUT from connect_ex().
            This value represents a connection attempt that timed out.

        Expected result:
            The result identifies port 80 and reports its state as
            "filtered", following the project's convention for timeouts.
        """
        mock_socket = mock_socket_class.return_value
        mock_socket.connect_ex.return_value = errno.ETIMEDOUT

        scanner = PortScanner()
        result = scanner.scan_port("127.0.0.1", 80)

        self.assertEqual(result["port"], 80)
        self.assertEqual(result["state"], "filtered")

