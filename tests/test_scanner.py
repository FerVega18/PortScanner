"""Verify how PortScanner interprets simulated TCP connection results."""

import errno
import socket
import unittest
from unittest.mock import MagicMock, patch

from portscanner.scanner import PortScanner


class PortScannerTests(unittest.TestCase):
    """Check the state reported for a single TCP connection attempt."""

    @patch("portscanner.scanner.socket.getservbyport", return_value="http")
    @patch("portscanner.scanner.socket.socket")
    def test_successful_connection_marks_port_open(
        self, mock_socket_class: MagicMock, mock_service_lookup: MagicMock
    ) -> None:
        """
        Verify that a successful TCP connection is reported as open.

        Scenario:
            The simulated socket returns 0 from connect_ex(), and the service
            lookup returns "http" for TCP port 80.

        Expected result:
            The result identifies port 80 and reports its state as "open".

        Args:
            mock_socket_class (MagicMock): Patched socket constructor.
            mock_service_lookup (MagicMock): Patched service-name lookup.

        Returns:
            None
        """
        mock_socket = mock_socket_class.return_value
        mock_socket.connect_ex.return_value = 0

        scanner = PortScanner()
        result = scanner.scan_port("127.0.0.1", 80)

        self.assertEqual(result["port"], 80)
        self.assertEqual(result["state"], "open")
        self.assertEqual(result["service"], "http")
        mock_service_lookup.assert_called_once_with(80)

    @patch("portscanner.scanner.socket.socket")
    def test_connection_timeout_marks_port_filtered(
        self, mock_socket_class: MagicMock
    ) -> None:
        """
        Verify how the scanner reports a connection timeout.

        Scenario:
            The simulated socket raises socket.timeout when connect_ex()
            attempts the connection.

        Expected result:
            The scanner returns the requested port with state "filtered",
            following the current convention for a connection timeout.

        Args:
            mock_socket_class (MagicMock): Patched socket constructor.

        Returns:
            None
        """
        mock_socket = mock_socket_class.return_value
        mock_socket.connect_ex.side_effect = socket.timeout

        scanner = PortScanner()
        result = scanner.scan_port("127.0.0.1", 80)

        self.assertEqual(result["port"], 80)
        self.assertEqual(result["state"], "filtered") 

    @patch("portscanner.scanner.socket.socket")
    def test_connection_refused_marks_port_closed(
        self, mock_socket_class: MagicMock
    ) -> None:
        """
        Verify how the scanner reports an explicit connection refusal.

        Scenario:
            The simulated socket raises ConnectionRefusedError when
            connect_ex() attempts the connection.

        Expected result:
            The result identifies port 80 and reports its state as "closed".

        Args:
            mock_socket_class (MagicMock): Patched socket constructor.

        Returns:
            None
        """
        mock_socket = mock_socket_class.return_value
        mock_socket.connect_ex.side_effect = ConnectionRefusedError

        scanner = PortScanner()
        result = scanner.scan_port("127.0.0.1", 80)

        self.assertEqual(result["port"], 80)
        self.assertEqual(result["state"], "closed")

    @patch("portscanner.scanner.socket.socket")
    def test_refused_connection_code_marks_port_closed(
        self, mock_socket_class: MagicMock
    ) -> None:
        """
        Verify that a refusal code is reported as a closed port.

        Scenario:
            The simulated socket returns errno.ECONNREFUSED from
            connect_ex(), representing a refused TCP connection.

        Expected result:
            The result identifies port 80 and reports its state as "closed".

        Args:
            mock_socket_class (MagicMock): Patched socket constructor.

        Returns:
            None
        """
        mock_socket = mock_socket_class.return_value
        mock_socket.connect_ex.return_value = errno.ECONNREFUSED

        scanner = PortScanner()
        result = scanner.scan_port("127.0.0.1", 80)

        self.assertEqual(result["port"], 80)
        self.assertEqual(result["state"], "closed")

    @patch("portscanner.scanner.socket.socket")
    def test_timeout_code_marks_port_filtered(
        self, mock_socket_class: MagicMock
    ) -> None:
        """
        Verify how the scanner classifies a returned timeout code.

        Scenario:
            The simulated socket returns errno.ETIMEDOUT from connect_ex().
            This value represents a connection attempt that timed out.

        Expected result:
            The result identifies port 80 and reports its state as
            "filtered", following the project's convention for timeouts.

        Args:
            mock_socket_class (MagicMock): Patched socket constructor.

        Returns:
            None
        """
        mock_socket = mock_socket_class.return_value
        mock_socket.connect_ex.return_value = errno.ETIMEDOUT

        scanner = PortScanner()
        result = scanner.scan_port("127.0.0.1", 80)

        self.assertEqual(result["port"], 80)
        self.assertEqual(result["state"], "filtered")

    @patch("portscanner.scanner.socket.socket")
    def test_summary_counts_failed_connection_attempt(
        self, socket_class: MagicMock
    ) -> None:
        """
        Verify that the scan summary includes failed connection attempts.

        Scenario:
            The simulated socket raises an unexpected error during a
            connection attempt, and the scanner records the state as "error".

        Expected result:
            The summary counts one attempted port and one error.

        Args:
            socket_class (MagicMock): Patched socket constructor.

        Returns:
            None
        """
        socket_class.return_value.connect_ex.side_effect = OSError(
            "Simulated socket failure"
        )
        scanner = PortScanner()

        result = scanner.scan_port("127.0.0.1", 80)
        summary = scanner.get_summary()

        self.assertEqual(result["state"], "error")
        self.assertEqual(summary["total_scanned"], 1)
        self.assertEqual(summary["error_count"], 1)

    @patch("portscanner.scanner.socket.socket")
    def test_new_scan_resets_failed_attempt_count(
        self, socket_class: MagicMock
    ) -> None:
        """
        Verify that failed attempts from a previous scan are not retained.

        Scenario:
            Two scans each encounter one simulated connection error.

        Expected result:
            Each scan summary reports one attempted port and one error,
            rather than accumulating the previous scan's failed attempt.

        Args:
            socket_class (MagicMock): Patched socket constructor.

        Returns:
            None
        """
        socket_class.return_value.connect_ex.side_effect = OSError(
            "Simulated socket failure"
        )
        scanner = PortScanner()

        scanner.scan_ports("127.0.0.1", [80])
        first_summary = scanner.get_summary()
        scanner.scan_ports("127.0.0.1", [80])
        second_summary = scanner.get_summary()

        self.assertEqual(first_summary["total_scanned"], 1)
        self.assertEqual(first_summary["error_count"], 1)
        self.assertEqual(second_summary["total_scanned"], 1)
        self.assertEqual(second_summary["error_count"], 1)